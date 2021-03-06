/**
 * @file detection_manger.h
 *
 * @author Boaz Lavon
 * @date 10/21
 */
#ifndef __DETECTION_MANAGER_H__
#define __DETECTION_MANAGER_H__

#include <iostream>
#include <fstream>
#include <unordered_set>
#include <memory>

#include "json/json.h"
#include "common_password_detector.h"
#include "identical_auth_detector.h"

using namespace std;

#define DETECTORS_COUNT (2)
enum class detection_result_e {

    NO_DETECTION              = 0b00,
    DETECTED_IDENTICAL_AUTH   = 0b01,
    DETECTED_COMMON_PASSWORD  = 0b10
};

class DetectionManager {

        /* Search, insertion, and removal have average constant-time complexity in unordered_set */
        shared_ptr<unordered_set<string>> secured_hosts;
        shared_ptr<unordered_set<string>> common_passwords;
        string captures_json_path;

        array<shared_ptr<GenericDetector>, DETECTORS_COUNT> detectors;
        array<detection_result_e, DETECTORS_COUNT> detection_results = {detection_result_e::DETECTED_IDENTICAL_AUTH, 
                                                                        detection_result_e::DETECTED_COMMON_PASSWORD};

        detection_result_e add_capture(Json::Value entry);

    public:
        DetectionManager(const string& secured_hosts_path, const string& common_passwords_path, const string& captures_json);
        void execute();
};

#endif /* __DETECTION_MANAGER_H__ */
