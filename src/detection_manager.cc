/**
 * @file detection_manager.cc
 *
 * @author Boaz Lavon
 
 * @date 10/21 */

#include <iostream>
#include "json/json.h"

#include "detection_manager.h"
#include "generic_detector.h"
#include "common_password_detector.h"
#include "identical_auth_detector.h"

using namespace std;

static
void 
validate_captures_json(
  const char *captures_json_path
) {

  Json::Value root;
  Json::Value entry;
  ifstream json_file(captures_json_path);
  if (!json_file) {
    cerr << "File \"" << captures_json_path << "\" could not be opened\n";
    throw runtime_error("Invalid JSON file");
  }

  json_file >> root;
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
#ifdef DEBUG
  cout << "JSON is valid" << "\n";
#endif
}


static
void
init_string_set_from_file(
  const char *strings_path,
  shared_ptr<unordered_set<string>>& strings_set
) {

  ifstream inputFile(strings_path);
  string line;

  if (!inputFile) {
    cerr << "File \"" << strings_path << "\" could not be opened\n";
    throw runtime_error("Cannot open " + string(strings_path));
  }

  while (getline(inputFile, line)) {
    strings_set->insert(line);
  }

#ifdef DEBUG
  cout << "Entries count:" << strings_set->size() << "\n";
#endif
}


DetectionManager::DetectionManager(
  const char *secured_hosts_path, 
  const char *common_passwords_path,
  const char *captures_json_path
) {

#ifdef DEBUG
  cout << "Secured HOSTs: " << secured_hosts_path << "\n\n";
#endif
  this->secured_hosts = make_shared<unordered_set<string>>();
  init_string_set_from_file(secured_hosts_path, this->secured_hosts);

#ifdef DEBUG
  cout << "Common Passwords: " << common_passwords_path << "\n\n";  
#endif
  this->common_passwords = make_shared<unordered_set<string>>();
  init_string_set_from_file(common_passwords_path, this->common_passwords);

#ifdef DEBUG
  cout << "Captures JSON: " << captures_json_path << "\n";
#endif
  validate_captures_json(captures_json_path);

  /* init detectors */
  this->captures_json_path = string(captures_json_path);
  this->identical_auth_detector  = make_shared<IdenticalAuthDetector>();
  this->detectors[0] = dynamic_pointer_cast<GenericDetector>(this->identical_auth_detector);

  this->common_password_detector = make_shared<CommonPasswordDetector>(secured_hosts, common_passwords);
  this->detectors[1] = dynamic_pointer_cast<GenericDetector>(this->common_password_detector);
}

detection_result_t 
DetectionManager::add_capture(
  Json::Value entry
) {

  int final_detection_result = NO_DETECTION;
  bool detection_result = false;

  for (size_t i = 0; i < DETECTORS_COUNT; ++i) {
    try {
      detection_result = this->detectors[i]->detect(entry);
    }
    catch (...) {
      cerr << "Error: Catched Exception";
      detection_result = false;
    }

    if (detection_result) {
      final_detection_result |= this->detection_results[i];
    }
  }

  return (detection_result_t)final_detection_result;
}

void
DetectionManager::execute(void) {

  Json::Value root;
  Json::Value entry;
  detection_result_t detection_result;

  ifstream json_file(this->captures_json_path);
  json_file >> root;

  for (Json::Value::ArrayIndex i = 0; i < root["requests"].size(); i++) {
      entry = root["requests"][i];
      detection_result = add_capture(entry);
      cout << (int)i << ")\t" << "ts: " << entry["timestamp"].asString() << "\tresult: " << (int)detection_result << "\n";
  }
}
