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

#include "json/json.h"
#include "common_password_detector.h"
#include "identical_auth_detector.h"
#include "commons.h"

using namespace std;
typedef enum detection_result_e {
    NO_DETECTION     = 0b00,
    DETECTED_IDENTICAL_AUTH   = 0b01,
    DETECTED_COMMON_PASSWORD  = 0b10
} detection_result_t;

class DetectionManager {

        /* Search, insertion, and removal have average constant-time complexity */
        unordered_set<string> secured_hosts;
        unordered_set<string> common_passwords;
        string captures_json_path;
        CommonPasswordDetector common_password_detector;
        IdenticalAuthDetector  identical_auth_detector;

        detection_result_t add_capture(Json::Value entry);

    public:
        DetectionManager(const char *secured_hosts_path, const char *common_passwords_path, const char *captures_json);
        result_t execute(void);
};

#endif /* __DETECTION_MANAGER_H__ */
