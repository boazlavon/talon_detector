/**
 * @file detection_manager.cc
 *
 * @author Boaz Lavon
 
 * @date 10/21 */

#include <iostream>
#include "json/json.h"

#include "commons.h"
#include "detection_manager.h"

using namespace std;

static
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

DetectionManager::DetectionManager(
  const char *secured_hosts_path, 
  const char *common_passwords_path,
  const char *captures_json_path
) {
  cout << "Secured HOSTs: " << secured_hosts_path << "\n";
  init_string_set_from_file(secured_hosts_path, this->secured_hosts);
  cout << "\n";

  cout << "Common Passwords: " << common_passwords_path << "\n";  cout << "\n";
  init_string_set_from_file(common_passwords_path, this->common_passwords);

  /* Validate JSON file */
  cout << "\n";
  cout << "Captures JSON: " << captures_json_path << "\n";
  validate_captures_json(captures_json_path);
  this->captures_json_path = string(captures_json_path);

  this->common_password_detector.set_secured_hosts(&(this->secured_hosts));
  this->common_password_detector.set_common_passwords(&(this->common_passwords));
}

// the most compact way is to build a regex from this list
result_t 
DetectionManager::init_string_set_from_file(
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


detection_result_t DetectionManager::add_capture(
  Json::Value entry
) {

  int final_detection_result = NO_DETECTION;
  bool detection_result = false;

  try {
     detection_result = this->common_password_detector.detect(entry);
  }
  catch (...) {
    cout << "Exception Catched";
    detection_result = false;
  }
  if (detection_result) {
    final_detection_result |= DETECTED_COMMON_PASSWORD;
  }

  return (detection_result_t)final_detection_result;
}

result_t DetectionManager::execute(void) {
  Json::Value root;
  Json::Value entry;
  detection_result_t detection_result;

  cout << this->captures_json_path << "\n";
  ifstream file(this->captures_json_path);
  file >> root;
  //cout << root;

  for (Json::Value::ArrayIndex i = 0; i < root["requests"].size(); i++) {
      entry = root["requests"][i];
      detection_result = add_capture(entry);
      cout << (int)i << ")\t" << "ts: " << entry["timestamp"].asString() << "\tresult: " << (int)detection_result << "\n";
  }
  return RESULT_SUCESS;
}
