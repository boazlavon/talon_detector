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

#include "json/json.h"
#include "date.h"

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

// static
// bool
// convert_timestamp_str(
//   string timestamp_str, 
//   chrono::duration<float>& time
// ) {

//   //const std::string in = "2018-12-09T00:00:00";
//                        //"2021-11-12T19:12:19.879Z"
//   std::stringstream ss(timestamp_str);

//   if (ss > std::chrono::parse("%FT%TZ", time))
//   {
//       typedef std::chrono::milliseconds ms;
//       ms d = std::chrono::duration_cast<ms>(time);
//       std::cout << "Date: " << d.count() << '\n';
//   }
//   else{
//       std::cout << "Error!\n";
//   }
// }#include "date.h"


static
time_t
convert_timestamp_str(
  string timestamp_str
) {    
    std::tm tm = {};
    const char *snext = ::strptime(timestamp_str.c_str(), "%Y-%m-%dT%H:%M:%S", &tm);
    if (NULL == snext) {
      return 0;
    }
    auto time_point = std::chrono::system_clock::from_time_t(std::mktime(&tm));
    time_t duration_ms = time_point.time_since_epoch() / std::chrono::milliseconds(1) + std::atof(snext) * 1000.0f;
    //std::cout << duration_ms << std::endl;
    return duration_ms;
}

bool 
IdenticalAuthDetector::detect(
  Json::Value& entry
) {

  string host = entry["host"].asString();
  string timestamp_str = entry["timestamp"].asString();
  // convert to timestamp
  time_t timestamp_ms = convert_timestamp_str(timestamp_str);
  cout << "timestamp_ms: " << timestamp_ms << "\n";
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

