/**
 * @file identical_auth_detector.cc
 *
 * @author Boaz Lavon
 
 * @date 10/21 */

#include <iostream>
#include <cassert>
#include <unordered_set>
#include <time.h>
#include <string>
#include <unordered_map>
#include <sstream>
#include <chrono>

#include "json/json.h"
#include "commons.h"
#include "identical_auth_detector.h"

using namespace std;

// void
// IdenticalAuthDetector::clean_queue(
//   time_t current_time
// ) {

//   shared_ptr<RequestEntry> iter;
//   while (this->requests_queue.size() &\
//          (current_time - this->requests_queue.front()->timestamp > this->max_gap_sec)
//   ) {
//     /* shared ptr will automaticly freed once the refference count zeros */
//     iter = this->requests_queue.pop();
//     this->hosts_map(iter->to_auth_string())
//     // remove from hosts map
//   }
// }

static
time_t
convert_timestamp_str_to_msec(
  string timestamp_str
) {    
    tm timestamp_tm = {};
    time_t timestamp_sec = 0, timestamp_msec = 0;
    char *snext = strptime(timestamp_str.c_str(), INPUT_TIMESTAMP_TEMPLATE, &timestamp_tm);
    if (NULL == snext) {
      return -1;
    }

    timestamp_sec = mktime(&timestamp_tm);
    if (-1 == timestamp_sec) {
      return -1;
    }

    timestamp_msec  = timestamp_sec * 1000; // convert to milliseconds
    timestamp_msec += (time_t)(atof(snext) * 1000.0f);  // add milliseconds from timestamp str
    return timestamp_msec;
}

bool 
IdenticalAuthDetector::detect(
  Json::Value& entry
) {

  /* Extract Propertires */
  string host = entry["host"].asString();
  string timestamp_str = entry["timestamp"].asString();
  time_t timestamp_msec = convert_timestamp_str_to_msec(timestamp_str);
  cout << "timestamp_ms: " << timestamp_msec << "\n";
  if (-1 == timestamp_msec) {
    return false;
  }

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

