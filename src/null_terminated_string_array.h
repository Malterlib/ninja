// Copyright 2023 Google Inc. All Rights Reserved.
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

#ifndef NINJA_NULL_TERMINATED_STRING_ARRAY_H_
#define NINJA_NULL_TERMINATED_STRING_ARRAY_H_

#include <set>
#include <string>
#include <vector>

struct NullTerminatedStringArray {
#ifdef _WIN32
  using String = std::wstring;
  using Char = wchar_t;
#else
  using String = std::string;
  using Char = char;
#endif

  void AddEnvironment(const String& environment,
                      std::set<String>& set_variables,
                      Char** system_environment);

  void AddUnsetEnvironment(Char** system_environment,
                           const std::set<String>& set_variables);

  void AddArguments(const String& arguments);

  Char** GetPointerArray();

#ifdef _WIN32
  Char* GetEnvironmentBlock();
#endif

  bool valid = false;

 private:
  std::vector<String> strings;
  std::vector<Char*> strings_pointers;

#ifdef _WIN32
  std::vector<wchar_t> environment_block;
#endif

  bool string_pointers_valid = false;
  bool environment_block_valid = false;
};

#endif  // NINJA_NULL_TERMINATED_STRING_ARRAY_H_
