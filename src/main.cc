/**
 * @file main.cc
 *
 * @author Boaz Lavon
 
 * @date 10/21 */

#include <iostream>
#include "detection_manager.h"

using namespace std;

enum class argv_params_e {

  ARGV_PNAME = 0,
  ARGV_SECURED_HOSTS_PATH,
  ARGV_PASSWORDS_PATH,
  ARGV_JSON_CAPTURES,

  NUM_OF_ARGV_PARAMS // last parameter in the enum
};

enum class result_e {

  RESULT_SUCESS = 0,
  RESULT_FAILURE,
  ERROR_INPUT_PARAMS

};

int main(
  int   argc, 
  char *argv[]
) {

  result_e result = result_e::RESULT_SUCESS;
  if (argc != (int)argv_params_e::NUM_OF_ARGV_PARAMS) {
    cerr << "Usage: " << argv[0] << " [SECURED_HOSTS_PATH] [COMMON_PASSWORDS_PATH] [JSON_CAPTURES_PATH]\n";
    return (int)result_e::ERROR_INPUT_PARAMS;
  }

  try {
    string secured_hosts_path(argv[(int)argv_params_e::ARGV_SECURED_HOSTS_PATH]);
    string common_passwords_path(argv[(int)argv_params_e::ARGV_PASSWORDS_PATH]);
    string json_captures_path(argv[(int)argv_params_e::ARGV_JSON_CAPTURES]);
    DetectionManager manager(secured_hosts_path, common_passwords_path, json_captures_path);
    manager.execute();
  } catch (...) {
    result = result_e::RESULT_FAILURE;
  }

  return (int)result;
}