/**
 * @file main.cc
 *
 * @author Boaz Lavon
 
 * @date 10/21 */

#include <cstdlib>
#include <cassert>
#include <string>
#include <iostream>
#include <time.h>
#include <sstream>
#include <fstream>
#include <unordered_set>
#include <algorithm>
#include <iterator>
#include <memory>


#include "detection_manager.h"

using namespace std;

enum argv_params_e {

  ARGV_PNAME              = 0,
  ARGV_SECURED_HOSTS_PATH  = 1,
  ARGV_PASSWORDS_PATH     = 2,
  ARGV_JSON_CAPTURES      = 3,

  NUM_OF_ARGV_PARAMS
};

typedef enum result_e : int {

  RESULT_SUCESS = 0,
  RESULT_FAILURE,
  ERROR_INPUT_PARAMS

} result_t;

int main(
  int   argc, 
  char *argv[]
) {

  result_t result = RESULT_SUCESS;
  if (argc != NUM_OF_ARGV_PARAMS) {
    cerr << "Usage: " << argv[0] << " [SECURED_HOSTS_PATH] [COMMON_PASSWORDS_PATH] [JSON_CAPTURES_PATH]\n";
    return ERROR_INPUT_PARAMS;
  }

  try {
    shared_ptr<DetectionManager> manager = make_unique<DetectionManager>(argv[ARGV_SECURED_HOSTS_PATH], 
                                                                         argv[ARGV_PASSWORDS_PATH],
                                                                         argv[ARGV_JSON_CAPTURES]);
    manager->execute();
  } catch (...) {
    result = RESULT_FAILURE;
  }

  return result;
}

