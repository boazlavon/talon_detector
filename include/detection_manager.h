/**
 * @file detection_manger.h
 *
 * @author Boaz Lavon
 * @date 10/21
 */
#ifndef __DETECTION_MANAGER_H__
#define __DETECTION_MANAGER_H__

#include <cstdlib>
#include <string>
#include <iostream>
#include <time.h>
#include <sstream>
#include <fstream>
#include <unordered_set>
#include <algorithm>
#include <iterator>
#include <memory>
#include <array>

#include "json/json.h"
#include "generic_detector.h"
#include "common_password_detector.h"
#include "identical_auth_detector.h"

using namespace std;

#define DETECTORS_COUNT (2)
typedef enum detection_result_e {
    NO_DETECTION     = 0b00,
    DETECTED_IDENTICAL_AUTH   = 0b01,
    DETECTED_COMMON_PASSWORD  = 0b10
} detection_result_t;

class DetectionManager {

        /* Search, insertion, and removal have average constant-time complexity */
        shared_ptr<unordered_set<string>> secured_hosts;
        shared_ptr<unordered_set<string>> common_passwords;
        string captures_json_path;

        array<shared_ptr<GenericDetector>, DETECTORS_COUNT> detectors;
        array<detection_result_t, DETECTORS_COUNT> detection_results = {DETECTED_IDENTICAL_AUTH, DETECTED_COMMON_PASSWORD};

        detection_result_t add_capture(Json::Value entry);

    public:
        DetectionManager(const string& secured_hosts_path, const string& common_passwords_path, const string& captures_json);
        void execute();
};

#endif /* __DETECTION_MANAGER_H__ */
