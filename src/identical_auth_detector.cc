/**
 * @file identical_auth_detector.cc
 *
 * @author Boaz Lavon
 
 * @date 10/21 */

#include <iostream>
#include <cassert>
#include <unordered_set>
#include <date.h>
#include "json/json.h"

#include "commons.h"
#include "identical_auth_detector.h"

using namespace std;

void
IdenticalAuthDetector::clean_queue(
  time_t current_time
) {

  shared_ptr<RequestEntry> iter;
  while (this->requests_queue.size() &\
         (current_time - this->requests_queue.front()->timestamp > this->max_gap_sec)
  ) {
    /* shared ptr will automaticly freed once the refference count zeros */
    iter = this->requests_queue.pop();
    this->hosts_map(iter->to_auth_string())
    // remove from hosts map
  }
}


bool 
IdenticalAuthDetector::detect(
  Json::Value& entry
) {

  string host = entry["host"].asString();
  string timestamp_str = entry["timestamp"].asString();
  // convert to timestamp
  //time_t timestamp = 0;
  string password = extract_password(entry);
  if (password.empty()) {
    return false;
  }
  string user = extract_user(entry);
  if (user.empty()) {
    return false;
  }

  // clean queue 
  // add entry to queue
  // add entry to host map

  // detect

  return true;
}

