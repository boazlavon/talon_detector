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
#include <queue>
#include <chrono>

#include "json/json.h"
#include "commons.h"
#include "identical_auth_detector.h"

using namespace std;

void
IdenticalAuthDetector::clean_queue(
  time_t current_time_msec
) {

  shared_ptr<RequestEntry> iter = nullptr;
  time_t diff = 0;
  string auth;

  while (this->requests_queue.size())
  {
    iter = this->requests_queue.front();
    diff = current_time_msec - iter->get_timestamp_msec();
    if (diff <= this->max_gap_msec) {
      break;
    }

    /* remove host from hosts map */
    auth = iter->get_auth();
    auto search = this->hosts_map.find(auth);
    if (search != this->hosts_map.end()) {
      auto auth_hosts = search->second;
      auth_hosts->erase(iter->get_host());
      if (!auth_hosts->size()) {
        this->hosts_map.erase(auth);
      }
    }

    this->requests_queue.pop();
  }
}

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

  shared_ptr<unordered_set<string>> auth_hosts = nullptr;
  /* Extract Propertires */
  string host = entry["host"].asString();
  string timestamp_str = entry["timestamp"].asString();
  time_t timestamp_msec = convert_timestamp_str_to_msec(timestamp_str);
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

  /* Update data stractures */
  this->clean_queue(timestamp_msec);
  this->requests_queue.push(make_shared<RequestEntry>(user, password, host, timestamp_msec));
  cout << "queue: " << this->requests_queue.size() << "\n";

  // auto s = this->requests_queue.size();
  // for (int i = 0; i < s; ++i ) {
  //   auto iter = this->requests_queue.front();
  //    cout <<  iter->get_timestamp_msec() << ": " << iter->get_auth() << " -> " << iter->get_host() << "\n";
  //   this->requests_queue.pop();
  //   this->requests_queue.push(iter);
  // }
  // cout << "\n";

  // add entry to host map
  string auth = this->requests_queue.back()->get_auth();
  auto search = this->hosts_map.find(auth);
  if (search == this->hosts_map.end()) {
    this->hosts_map[auth] = make_shared<unordered_set<string>>();
    search = this->hosts_map.find(auth);
  }

  auth_hosts = search->second; // shared pointer to unordered set.
  auth_hosts->insert(host);
  return (auth_hosts->size() > 1); 
}