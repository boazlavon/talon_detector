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
#include "identical_auth_detector.h"

using namespace std;

static
time_t
convert_timestamp_str_to_msec(
  const string& timestamp_str
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
    timestamp_msec += (time_t)(atof(snext) * 1000.0f); // add milliseconds from timestamp str
    return timestamp_msec;
}

static 
void
find_different_host(
  shared_ptr<hosts_map_t> hosts_map,
  string new_request_host,
  shared_ptr<RequestEntry>& different_host_request
) {

  /* There is not specific requirment of which host to choose in case there is more than one different host.
     So just pick the first one that is different.
  */
  hosts_map_t::iterator iter = hosts_map->begin();
  while (hosts_map->size() && iter != hosts_map->end()) {
    if (iter->first != new_request_host) {
      different_host_request = iter->second->front();
      break;
    }
    iter++;
  }
}


void
IdenticalAuthDetector::clean_queue(
  shared_ptr<requests_queue_t> requests_queue,
  const time_t current_time_msec
) {

  shared_ptr<RequestEntry> iter = nullptr;
  time_t diff = 0;

  while (requests_queue->size())
  {
    iter = requests_queue->front();
    diff = current_time_msec - iter->get_timestamp_msec();
    if (diff <= this->max_gap_msec) {
      break;
    }

    requests_queue->pop();
  }
}

void
IdenticalAuthDetector::clean_host_queues(
  shared_ptr<hosts_map_t> hosts_map,
  const time_t current_time_msec
) {

  shared_ptr<requests_queue_t> requests_queue = nullptr;
  hosts_map_t::iterator iter = hosts_map->begin();
  while (hosts_map->size() && iter != hosts_map->end()) {
      /* request queue for a specific host */
      requests_queue = iter->second;

      /* remove all the requests that are older than 10sec since this new request timestamp */
      this->clean_queue(requests_queue, current_time_msec);

      /* if there are not more requests under this host, remove the host from the hosts map */
      if (!requests_queue->size()) {
        iter = hosts_map->erase(iter);
      } else {
        iter++;
      }
  }
}


bool 
IdenticalAuthDetector::detect(
  const Json::Value& entry
) {

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
  shared_ptr<RequestEntry> request = make_shared<RequestEntry>(user, password, host, timestamp_msec);

  /* find a hosts map belong to this user & password pair - auth */
  string auth = request->get_auth();
  auto search_host_map = this->auth_map.find(auth);
  if (search_host_map == this->auth_map.end()) {
    this->auth_map.insert({auth, make_shared<hosts_map_t>()});
    search_host_map = this->auth_map.find(auth);
  }

  /* clean host queues from requests that are older than 10sec since this new request */
  shared_ptr<hosts_map_t> hosts_map = search_host_map->second;
  this->clean_host_queues(hosts_map, timestamp_msec);

  /* add a new request - search the host queue or create it */
  auto search_host_queue = hosts_map->find(host);
  if (search_host_queue == hosts_map->end()) {
    hosts_map->insert({host, make_shared<requests_queue_t>()});
    search_host_queue = hosts_map->find(host);
  }

  shared_ptr<requests_queue_t> requests_queue = search_host_queue->second;
  requests_queue->push(request);

#ifdef DEBUG
  /* print queue */
  cout << auth << "\n";
  shared_ptr<RequestEntry> iter_requests = nullptr;
  for (auto& iter_hosts: (*hosts_map)) {
      cout << "\t" << iter_hosts.first << "\n";
      auto s = iter_hosts.second->size();
      for (int i = 0; i < (int)s; ++i) {
         iter_requests = iter_hosts.second->front();
         cout <<  "\t\t" << iter_requests->get_timestamp_msec() << "\n";
         iter_hosts.second->pop();
         iter_hosts.second->push(iter_requests);
      }
  }
  cout << "\n";
#endif

  /* If there is a different host for with this auth (user&password) - it's in the detection window.
     Therefore, print detection details */
  if (hosts_map->size() > 1) {
    shared_ptr<RequestEntry> different_host_request = nullptr;
    find_different_host(hosts_map, request->get_host(), different_host_request);
    if (nullptr != different_host_request) {
      time_t diff_msec = request->get_timestamp_msec() - different_host_request->get_timestamp_msec();
      cout << "Identical User/Password pair found diff under " << (this->max_gap_msec / 1000) << "s" << ": " << diff_msec << "ms in host " << host << " user/pass: " << user << "/" << password << "\n";
    } else {
      cerr << "Identical Auth Detector: Error\n";
    }
  }

  return (hosts_map->size() > 1); 
}