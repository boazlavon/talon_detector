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
#include <time.h>

#include "json/json.h"
#include "commons.h"
#include "generic_detector.h"

using namespace std;

class RequestEntry {
	string user;
	string password;
	string url;
	time_t timestamp;
	void clean_queue(time_t current_time);
	string to_auth_string(void) { return "password=" + this->password + "user=" + this->user; }

	public:
		RequestEntry(string user, string password, string url, time_t timestamp) : \
		user(user), password(password), url(url), timestamp(timestamp) {}
};

#define MAX_GAP_SEC (10)
class IdenticalAuthDetector : GenericDetector {
	/* map. (user, password) -> unsorted set of hosts */
	//unsorted_map<string, shared_ptr<unordered_set<string> > > hosts_map;	

	/* queue of items (user, password, time, host) */
	//queue<shared_ptr<RequestEntry>> requests_queue;
    //requests_queue.push_back(make_shared<RequestEntry>(10, 2));

	time_t max_gap_sec;

    public:
		IdenticalAuthDetector() : max_gap_sec(MAX_GAP_SEC) {}
    	virtual bool detect(Json::Value& entry);
};

#endif /* __IDENTICAL_AUTH_DETECTOR_H__ */
