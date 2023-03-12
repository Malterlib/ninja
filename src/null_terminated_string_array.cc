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

#include "null_terminated_string_array.h"

#include <cstring>
#include <map>

#include "util.h"

#ifdef _WIN32
#define find_char std::wcschr
#else
#define find_char std::strchr
#endif

void NullTerminatedStringArray::AddEnvironment(const String& environment,
                                               std::set<String>& set_variables,
                                               Char** system_environment) {
  valid = true;
  string_pointers_valid = false;
  environment_block_valid = false;

  std::map<String, const Char*> system_env_map;
  if (system_environment) {
    for (Char** env_entry = system_environment; *env_entry; ++env_entry) {
      const Char* value = find_char(*env_entry, '=');
      if (!value)
        continue;

      String name(const_cast<const Char*>(*env_entry), value);
      if (set_variables.find(name) != set_variables.end())
        continue;

      system_env_map[std::move(name)] = *env_entry;
    }
  }

  const Char* parse = environment.c_str();
  while (parse && *parse) {
    const Char* start_line = parse;
    const Char* value = find_char(parse, '=');
    if (!value) {
      if (!system_environment)
        Fatal("environment variable missing '='", value);

      const Char* end_line = find_char(start_line, '\n');
      String name;
      if (end_line)
        name = String(start_line, end_line);
      else
        name = start_line;

      auto system_line = system_env_map.find(name);
      if (system_line != system_env_map.end())
        strings.push_back(system_line->second);

      parse = end_line;
      if (parse)
        ++parse;

      continue;
    }

    String env_line(start_line, value);
    ++value;

    set_variables.insert(env_line);
    env_line.push_back('=');

    const Char* end_line = find_char(value, '\n');

    while (*value && (!end_line || value != end_line)) {
      Char character = *value;
      if (character == '\\') {
        switch (value[1]) {
        case 'n':
          env_line.push_back('\n');
          value += 2;
          continue;
        case '\\':
          env_line.push_back('\\');
          value += 2;
          continue;
        default:
          break;
        }
      }

      env_line.push_back(*value);
      ++value;
    }

    strings.push_back(std::move(env_line));

    parse = end_line;
    if (parse)
      ++parse;
  }
}

void NullTerminatedStringArray::AddUnsetEnvironment(
    Char** system_environment, const std::set<String>& set_variables) {
  valid = true;
  string_pointers_valid = false;
  environment_block_valid = false;

  for (Char** env_entry = system_environment; *env_entry; ++env_entry) {
    const Char* value = find_char(*env_entry, '=');
    if (!value)
      continue;

    String name(const_cast<const Char*>(*env_entry), value);
    if (set_variables.find(name) != set_variables.end())
      continue;

    strings.push_back(*env_entry);
  }
}

void NullTerminatedStringArray::AddArguments(const String& arguments) {
  if (arguments.empty())
    return;

  const Char* parse = arguments.c_str();
  String next_arg;
  Char parsing_escape = 0;
  while (*parse) {
    Char character = *parse;
    if (parsing_escape) {
      if (character == parsing_escape) {
        parsing_escape = 0;
      } else if (character == '\\') {
        if (parse[1] == parsing_escape) {
          next_arg.push_back(parsing_escape);
          parse += 2;
          continue;
        } else if (parse[1] == '\\') {
          next_arg.push_back('\\');
          parse += 2;
          continue;
        }
        next_arg.push_back(character);
      } else {
        next_arg.push_back(character);
      }
    } else {
      if (character == '"' || character == '\'') {
        parsing_escape = character;
      } else if (character == ' ') {
        strings.push_back(std::move(next_arg));
        next_arg.clear();
      } else {
        next_arg.push_back(character);
      }
    }
    ++parse;
  }

  strings.push_back(std::move(next_arg));
}

auto NullTerminatedStringArray::GetPointerArray() -> Char** {
  if (!string_pointers_valid) {
    string_pointers_valid = true;
    for (auto& string : strings)
      strings_pointers.push_back(const_cast<Char*>(string.c_str()));
    strings_pointers.push_back(NULL);
  }

  return strings_pointers.data();
}

#ifdef _WIN32
auto NullTerminatedStringArray::GetEnvironmentBlock() -> Char* {
  if (!environment_block_valid) {
    environment_block_valid = true;
    for (auto& string : strings)
      environment_block.insert(environment_block.end(), string.c_str(),
                               string.c_str() + string.size() + 1);
    environment_block.push_back(0);
  }

  return environment_block.data();
}
#endif
