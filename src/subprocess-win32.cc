// Copyright 2012 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "subprocess.h"

#include <assert.h>
#include <stdio.h>
#include <codecvt>

#include <algorithm>

#include "build_log.h"
#include "null_terminated_string_array.h"
#include "util.h"

using namespace std;

namespace {
NullTerminatedStringArray overridden_environment;
std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
}  // namespace

Subprocess::Subprocess(SubprocessArguments&& args)
    : child_(NULL), overlapped_(), is_reading_(false), args_(std::move(args)) {}

Subprocess::~Subprocess() {
  if (pipe_) {
    if (!CloseHandle(pipe_))
      Win32Fatal("CloseHandle");
  }
  // Reap child if forgotten.
  if (child_)
    Finish();
}

void Subprocess::OverrideEnvironment(const std::string& environment) {
  std::set<std::wstring> overridden_variables;
  overridden_environment.AddEnvironment(converter.from_bytes(environment),
                                        overridden_variables, _wenviron);
  overridden_environment.GetPointerArray();
  overridden_environment.GetEnvironmentBlock();

  BuildLog::LogEntry::GlobalEnvironmentHash(environment, true);
}

void Subprocess::AppendEnvironment(const std::string& environment) {
  std::set<std::wstring> overridden_variables;
  overridden_environment.AddEnvironment(converter.from_bytes(environment),
                                        overridden_variables, nullptr);
  overridden_environment.AddUnsetEnvironment(_wenviron, overridden_variables);
  overridden_environment.GetPointerArray();
  overridden_environment.GetEnvironmentBlock();

  BuildLog::LogEntry::GlobalEnvironmentHash(environment, false);
}

HANDLE Subprocess::SetupPipe(HANDLE ioport) {
  char pipe_name[100];
  snprintf(pipe_name, sizeof(pipe_name),
           "\\\\.\\pipe\\ninja_pid%lu_sp%p", GetCurrentProcessId(), this);

  pipe_ = ::CreateNamedPipeA(pipe_name,
                             PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                             PIPE_TYPE_BYTE,
                             PIPE_UNLIMITED_INSTANCES,
                             0, 0, INFINITE, NULL);
  if (pipe_ == INVALID_HANDLE_VALUE)
    Win32Fatal("CreateNamedPipe");

  if (!CreateIoCompletionPort(pipe_, ioport, (ULONG_PTR)this, 0))
    Win32Fatal("CreateIoCompletionPort");

  memset(&overlapped_, 0, sizeof(overlapped_));
  if (!ConnectNamedPipe(pipe_, &overlapped_) &&
      GetLastError() != ERROR_IO_PENDING) {
    Win32Fatal("ConnectNamedPipe");
  }

  // Get the write end of the pipe as a handle inheritable across processes.
  HANDLE output_write_handle =
      CreateFileA(pipe_name, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
  HANDLE output_write_child;
  if (!DuplicateHandle(GetCurrentProcess(), output_write_handle,
                       GetCurrentProcess(), &output_write_child,
                       0, TRUE, DUPLICATE_SAME_ACCESS)) {
    Win32Fatal("DuplicateHandle");
  }
  CloseHandle(output_write_handle);

  return output_write_child;
}

static std::wstring NormalizeArguments(NullTerminatedStringArray& parsed_args,
                                       std::wstring const& command) {
  parsed_args.AddArguments(command);
  auto* parsed_args_pointers = parsed_args.GetPointerArray();

  if (!*parsed_args_pointers)
    Fatal("subprocess: command was not specified");

  // Rules:
  // 2N     backslashes   + " ==> N backslashes and begin/end quote
  // 2N + 1 backslashes   + " ==> N backslashes + literal "
  // N      backslashes       ==> N backslashes

  std::wstring return_string;
  for (wchar_t** arg = parsed_args_pointers; *arg; ++arg) {
    if (!return_string.empty())
      return_string.push_back(' ');

    if (!**arg)
      return_string += L"\"\"";
    else if (std::wcschr(*arg, ' ') || std::wcschr(*arg, '"')) {
      return_string += L"\"";

      wchar_t const* parse = *arg;
      size_t backslashes = 0;
      while (*parse) {
        wchar_t character = *parse;
        if (character == '\"') {
          for (size_t i = 0; i < backslashes; ++i)
            return_string.push_back('\\');
          return_string += L"\\\"";
          backslashes = 0;
        } else if (character == '\\')
          ++backslashes;
        else {
          backslashes = 0;
          return_string.push_back(character);
        }
        ++parse;
      }

      for (size_t i = 0; i < backslashes; ++i)
        return_string.push_back('\\');

      return_string += L"\"";
    } else
      return_string += *arg;
  }

  return return_string;
}

bool Subprocess::Start(SubprocessSet* set) {
  HANDLE child_pipe = SetupPipe(set->ioport_);

  SECURITY_ATTRIBUTES security_attributes;
  memset(&security_attributes, 0, sizeof(SECURITY_ATTRIBUTES));
  security_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
  security_attributes.bInheritHandle = TRUE;
  // Must be inheritable so subprocesses can dup to children.
  HANDLE nul =
      CreateFileA("NUL", GENERIC_READ,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  &security_attributes, OPEN_EXISTING, 0, NULL);
  if (nul == INVALID_HANDLE_VALUE)
    Fatal("couldn't open nul");

  STARTUPINFOW startup_info;
  memset(&startup_info, 0, sizeof(startup_info));
  startup_info.cb = sizeof(STARTUPINFO);
  if (!args_.use_console_) {
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    startup_info.hStdInput = nul;
    startup_info.hStdOutput = child_pipe;
    startup_info.hStdError = child_pipe;
  }
  // In the console case, child_pipe is still inherited by the child and closed
  // when the subprocess finishes, which then notifies ninja.

  PROCESS_INFORMATION process_info;
  memset(&process_info, 0, sizeof(process_info));

  // Ninja handles ctrl-c, except for subprocesses in console pools.
  DWORD process_flags = args_.use_console_ ? 0 : CREATE_NEW_PROCESS_GROUP;

  std::wstring command_wide = converter.from_bytes(args_.command_);

  NullTerminatedStringArray parsed_args;
  wchar_t* application_path = nullptr;
  if (args_.command_raw_) {
    command_wide = NormalizeArguments(parsed_args, command_wide);
    application_path = *parsed_args.GetPointerArray();
  }

  NullTerminatedStringArray merged_environment;
  wchar_t* env_block = nullptr;

  if (!args_.environment_.empty()) {
    std::set<std::wstring> set_variables;
    merged_environment.AddEnvironment(converter.from_bytes(args_.environment_),
                                      set_variables, nullptr);

    if (overridden_environment.valid) {
      merged_environment.AddUnsetEnvironment(
          overridden_environment.GetPointerArray(), set_variables);
    } else {
      merged_environment.AddUnsetEnvironment(_wenviron, set_variables);
    }

    env_block = merged_environment.GetEnvironmentBlock();
  } else if (overridden_environment.valid) {
    env_block = overridden_environment.GetEnvironmentBlock();
  }

  if (env_block)
    process_flags |= CREATE_UNICODE_ENVIRONMENT;

  wchar_t* cwd_wide_ptr = nullptr;
  wstring cwd_wide;
  if (!args_.command_cwd_.empty()) {
    cwd_wide = converter.from_bytes(args_.command_cwd_);
    cwd_wide_ptr = const_cast<wchar_t*>(cwd_wide.c_str());
  }

  // Do not prepend 'cmd /c' on Windows, this breaks command
  // lines greater than 8,191 chars.
  if (!CreateProcessW(application_path,
                      const_cast<wchar_t*>(command_wide.c_str()), nullptr,
                      nullptr, /* inherit handles */ TRUE, process_flags,
                      env_block, cwd_wide_ptr, &startup_info, &process_info)) {
    DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND) {
      // File (program) not found error is treated as a normal build
      // action failure.
      if (child_pipe)
        CloseHandle(child_pipe);
      CloseHandle(pipe_);
      CloseHandle(nul);
      pipe_ = NULL;
      // child_ is already NULL;
      buf_ = "CreateProcess failed: The system cannot find the file "
          "specified.\n";
      return true;
    } else {
      fprintf(stderr, "\nCreateProcess failed. Command attempted:\n\"%s\"\n",
              args_.command_.c_str());
      const char* hint = NULL;
      // ERROR_INVALID_PARAMETER means the command line was formatted
      // incorrectly. This can be caused by a command line being too long or
      // leading whitespace in the command. Give extra context for this case.
      if (error == ERROR_INVALID_PARAMETER) {
        if (args_.command_.length() > 0 && 
            (args_.command_[0] == ' ' || args_.command_[0] == '\t'))
          hint = "command contains leading whitespace";
        else
          hint = "is the command line too long?";
      }
      Win32Fatal("CreateProcess", hint);
    }
  }

  // Close pipe channel only used by the child.
  if (child_pipe)
    CloseHandle(child_pipe);
  CloseHandle(nul);

  CloseHandle(process_info.hThread);
  child_ = process_info.hProcess;

  return true;
}

void Subprocess::OnPipeReady() {
  DWORD bytes;
  if (!GetOverlappedResult(pipe_, &overlapped_, &bytes, TRUE)) {
    if (GetLastError() == ERROR_BROKEN_PIPE) {
      CloseHandle(pipe_);
      pipe_ = NULL;
      return;
    }
    Win32Fatal("GetOverlappedResult");
  }

  if (is_reading_ && bytes)
    buf_.append(overlapped_buf_, bytes);

  memset(&overlapped_, 0, sizeof(overlapped_));
  is_reading_ = true;
  if (!::ReadFile(pipe_, overlapped_buf_, sizeof(overlapped_buf_),
                  &bytes, &overlapped_)) {
    if (GetLastError() == ERROR_BROKEN_PIPE) {
      CloseHandle(pipe_);
      pipe_ = NULL;
      return;
    }
    if (GetLastError() != ERROR_IO_PENDING)
      Win32Fatal("ReadFile");
  }

  // Even if we read any bytes in the readfile call, we'll enter this
  // function again later and get them at that point.
}

ExitStatus Subprocess::Finish() {
  if (!child_)
    return ExitFailure;

  // TODO: add error handling for all of these.
  WaitForSingleObject(child_, INFINITE);

  DWORD exit_code = 0;
  GetExitCodeProcess(child_, &exit_code);

  CloseHandle(child_);
  child_ = NULL;

  return exit_code == 0              ? ExitSuccess :
         exit_code == CONTROL_C_EXIT ? ExitInterrupted :
                                       ExitFailure;
}

bool Subprocess::Done() const {
  return pipe_ == NULL;
}

const string& Subprocess::GetOutput() const {
  return buf_;
}

HANDLE SubprocessSet::ioport_;

SubprocessSet::SubprocessSet() {
  ioport_ = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
  if (!ioport_)
    Win32Fatal("CreateIoCompletionPort");
  if (!SetConsoleCtrlHandler(NotifyInterrupted, TRUE))
    Win32Fatal("SetConsoleCtrlHandler");
}

SubprocessSet::~SubprocessSet() {
  Clear();

  SetConsoleCtrlHandler(NotifyInterrupted, FALSE);
  CloseHandle(ioport_);
}

BOOL WINAPI SubprocessSet::NotifyInterrupted(DWORD dwCtrlType) {
  if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_BREAK_EVENT) {
    if (!PostQueuedCompletionStatus(ioport_, 0, 0, NULL))
      Win32Fatal("PostQueuedCompletionStatus");
    return TRUE;
  }

  return FALSE;
}

Subprocess* SubprocessSet::Add(SubprocessArguments&& args) {
  Subprocess* subprocess = new Subprocess(std::move(args));
  if (!subprocess->Start(this)) {
    delete subprocess;
    return 0;
  }
  if (subprocess->child_)
    running_.push_back(subprocess);
  else
    finished_.push(subprocess);
  return subprocess;
}

bool SubprocessSet::DoWork() {
  DWORD bytes_read;
  Subprocess* subproc;
  OVERLAPPED* overlapped;

  if (!GetQueuedCompletionStatus(ioport_, &bytes_read, (PULONG_PTR)&subproc,
                                 &overlapped, INFINITE)) {
    if (GetLastError() != ERROR_BROKEN_PIPE)
      Win32Fatal("GetQueuedCompletionStatus");
  }

  if (!subproc) // A NULL subproc indicates that we were interrupted and is
                // delivered by NotifyInterrupted above.
    return true;

  subproc->OnPipeReady();

  if (subproc->Done()) {
    vector<Subprocess*>::iterator end =
        remove(running_.begin(), running_.end(), subproc);
    if (running_.end() != end) {
      finished_.push(subproc);
      running_.resize(end - running_.begin());
    }
  }

  return false;
}

Subprocess* SubprocessSet::NextFinished() {
  if (finished_.empty())
    return NULL;
  Subprocess* subproc = finished_.front();
  finished_.pop();
  return subproc;
}

void SubprocessSet::Clear() {
  for (vector<Subprocess*>::iterator i = running_.begin();
       i != running_.end(); ++i) {
    // Since the foreground process is in our process group, it will receive a
    // CTRL_C_EVENT or CTRL_BREAK_EVENT at the same time as us.
    if ((*i)->child_ && !(*i)->args_.use_console_) {
      if (!GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT,
                                    GetProcessId((*i)->child_))) {
        Win32Fatal("GenerateConsoleCtrlEvent");
      }
    }
  }
  for (vector<Subprocess*>::iterator i = running_.begin();
       i != running_.end(); ++i)
    delete *i;
  running_.clear();
}
