/**
 * @file common_password_detector.cc
 *
 * @author Boaz Lavon
 * @date 10/21 
 */

#include <iostream>
#include <cassert>
#include <unordered_set>
#include <memory>

#include "json/json.h"
#include "common_password_detector.h"

using namespace std;

bool 
CommonPasswordDetector::detect(
  const Json::Value& entry
) {

  if (!entry.isMember("host")) {
    return false;
  }

  /* is secured host ? */
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

