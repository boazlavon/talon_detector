/**
 * @file detection_manager.cc
 *
 * @author Boaz Lavon
 
 * @date 10/21 */

#include <iostream>
#include <cassert>
#include <unordered_set>

#include "json/json.h"

#include "commons.h"
#include "common_password_detector.h"

using namespace std;

CommonPasswordDetector::CommonPasswordDetector() { 
  this->secured_hosts = NULL;
  this->common_passwords = NULL;
}

void 
CommonPasswordDetector::set_secured_hosts(
  unordered_set<string> *secured_hosts
) {
  this->secured_hosts = secured_hosts;
}

void CommonPasswordDetector::set_common_passwords(
  unordered_set<string> *set_common_passwords
) {
  this->common_passwords = set_common_passwords;
}

bool 
CommonPasswordDetector::detect(
  Json::Value& entry
) {

  assert(this->common_passwords != NULL);
  assert(this->secured_hosts != NULL);

  if (!entry.isMember("host")) {
    return false;
  }

  /* is secured HOST */
  string host = entry["host"].asString();
  auto search_host = this->secured_hosts->find(host);
  if (search_host== this->secured_hosts->end()) {
    return false;
  } 

  string password = extract_password(entry);
  if (password.empty()) {
    return false;
  }

  /* is common password ? */
  auto search_password = this->common_passwords->find(password);
  if (search_password == this->common_passwords->end()) {
    return false;
  } 

  cout << "Common password found: " << password << " on secure host " << host << "\n";
  return true;
}

