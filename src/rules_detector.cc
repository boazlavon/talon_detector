/**
 * @file rules_detector.cc
 *
 * @author Boaz Lavon
 
 * @date 10/21 */

#include <iostream>

#include <commons.h>
#include <rules_detector.h>

using namespace std;

RulesDetector::RulesDetector(
  char *secured_urls_path, 
  char *common_passwords_path
) {

  cout << "Secured URLs: " << secured_urls_path << "\n";
  init_string_set_from_file(secured_urls_path, secured_urls);
  cout << "\n";

  cout << "Common Passwords: " << common_passwords_path << "\n";
  init_string_set_from_file(common_passwords_path, common_passwords);
  cout << "\n";
}

// the most compact way is to build a regex from this list
result_t 
RulesDetector::init_string_set_from_file(
  char *strings_path,
  unordered_set<string>& strings_set
) {

  result_t result = RESULT_SUCESS;
  ifstream inputFile(strings_path);
  string line;

  if(!inputFile) {
    cerr << "File \"" << strings_path << "\" could not be opened\n";
    result = ERROR_OPEN_FILE;
    goto l_exit;
  }

  while (getline(inputFile, line)) {
    strings_set.insert(line);
  }

  cout << "Entries count:" << strings_set.size() << "\n";

  //for (auto ptr : strings_set) {
  //   cout << ptr << "\n";
  //}
  cout << "\n";

l_exit:
  return result;
}


detection_result_t RulesDetector::add_capture(int a) {
  cout << a;
  return COMMON_PASSWORD;
}