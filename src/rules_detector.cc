/**
 * @file rules_detector.cc
 *
 * @author Boaz Lavon
 
 * @date 10/21 */

#include <iostream>
#include "json/json.h"

#include "commons.h"
#include "rules_detector.h"

using namespace std;

void validate_captures_json(
  const char *captures_json_path
) {
  Json::Value root;
  Json::Value entry;

  ifstream file(captures_json_path);
  file >> root;
  if (!root.isMember("requests") || !root["requests"].size()) {
    throw runtime_error("Invalid JSON file");
  }

  for (Json::Value::ArrayIndex i = 0; i < root["requests"].size(); i++) {
      entry = root["requests"][i];
      if (!entry.isMember("content") || \
          !entry.isMember("host") || \
          !entry.isMember("timestamp") || \
          !entry.isMember("url")) {
        throw runtime_error("Invalid JSON file");
      }
  }
  cout << "JSON is valid" << "\n";
}

RulesDetector::RulesDetector(
  const char *secured_urls_path, 
  const char *common_passwords_path,
  const char *captures_json_path
) {
  cout << "Secured URLs: " << secured_urls_path << "\n";
  init_string_set_from_file(secured_urls_path, secured_urls);
  cout << "\n";

  cout << "Common Passwords: " << common_passwords_path << "\n";  cout << "\n";
  init_string_set_from_file(common_passwords_path, common_passwords);

  /* Validate JSON file */
  cout << "\n";
  cout << "Captures JSON: " << captures_json_path << "\n";
  //validate_captures_json(captures_json_path);
  this->captures_json_path = string(captures_json_path);
}

// the most compact way is to build a regex from this list
result_t 
RulesDetector::init_string_set_from_file(
  const char *strings_path,
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
  //cout << "\n";

l_exit:
  return result;
}


detection_result_t RulesDetector::add_capture(
  Json::Value entry
) {

  detection_result_t detection_result = NO_DETECTION;
  // iterate detectors
  cout << entry;
  cout << "\n";
  return detection_result;
}

void RulesDetector::execute(void) {
  Json::Value root;
  Json::Value entry;
  detection_result_t detection_result;

  cout << this->captures_json_path << "\n";
  ifstream file(this->captures_json_path);
  file >> root;
  cout << root;

  for (Json::Value::ArrayIndex i = 0; i < root["requests"].size(); i++) {
      entry = root["requests"][i];
      detection_result = add_capture(entry);
  }
  return RESULT_SUCESS;
}
