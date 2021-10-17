/**
 * @file identical_auth_detector.h
 *
 * @author Boaz Lavon
 * @date 10/21
 */
#ifndef __IDENTICAL_AUTH_DETECTOR_H__
#define __IDENTICAL_AUTH_DETECTOR_H__

#include <memory>
#include <ctime>

#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <time.h>

#include "json/json.h"
#include "generic_detector.h"

using namespace std;

#define MAX_GAP_SEC (10)
#define MAX_GAP_MSEC (MAX_GAP_SEC * 1000)
#define INPUT_TIMESTAMP_TEMPLATE ("%Y-%m-%dT%H:%M:%S")

class RequestEntry {
	string user;
	string password;
	string host;
	time_t timestamp_msec;

	public:
		RequestEntry(string user, string password, string host, time_t timestamp_msec) : \
					 user(user), password(password), host(host), timestamp_msec(timestamp_msec) {}
		time_t get_timestamp_msec() { return this->timestamp_msec; }
		string get_auth() { return "user=" + this->user + "&password=" + this->password; }
		string get_host() { return this->host; }
};

using requests_queue_t = queue<shared_ptr<RequestEntry>> ;
using hosts_map_t      = unordered_map<string, shared_ptr<requests_queue_t>>; // host -> requests queue
using auth_map_t       = unordered_map<string, shared_ptr<hosts_map_t>>;      // auth (user&password) -> hosts map

class IdenticalAuthDetector : public GenericDetector {
	auth_map_t auth_map;
	time_t max_gap_msec;
	void clean_queue(shared_ptr<requests_queue_t> requests_queue, const time_t current_time_msec);
	void clean_host_queues(shared_ptr<hosts_map_t> hosts_map, const time_t current_time_msec);

    public:
		IdenticalAuthDetector() : max_gap_msec(MAX_GAP_MSEC) {}
    	virtual bool detect(const Json::Value& entry);
};

#endif /* __IDENTICAL_AUTH_DETECTOR_H__ */
