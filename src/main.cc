/**
 * @file rules_detector.cc
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

#include "commons.h"
#include "detection_manager.h"

using namespace std;

enum argv_params_e {

  ARGV_PNAME              = 0,
  ARGV_SECURED_HOSTS_PATH  = 1,
  ARGV_PASSWORDS_PATH     = 2,
  ARGV_JSON_CAPTURES      = 3,

  NUM_OF_ARGV_PARAMS
};

int main(
  int   argc, 
  char *argv[]
) {
  result_t result = RESULT_SUCESS;

  assert(argc == NUM_OF_ARGV_PARAMS);
  cout << "You have entered " << argc
        << " arguments:" << "\n";
  
  for (int i = 0; i < argc; ++i)
      cout << argv[i] << "\n\n";

  auto detector = make_unique<DetectionManager>(argv[ARGV_SECURED_HOSTS_PATH], 
                                                argv[ARGV_PASSWORDS_PATH],
                                                argv[ARGV_JSON_CAPTURES]);
  detector->execute();

  return result;
}

