/**
 * @file rules_detector.h
 *
 * @author Boaz Lavon
 * @date 10/21
 */
#ifndef __RULES_DETECTOR_H__
#define __RULES_DETECTOR_H__

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
#include "commons.h"

using namespace std;

typedef enum detection_result_e{
    NO_DETECTION     = 0b00,
    IDENTICAL_AUTH   = 0b01,
    COMMON_PASSWORD  = 0b10
} detection_result_t;

class RulesDetector {
    public:
        // List of Detectors - Generic class
        // return a result from execution
        RulesDetector(const char *secured_urls_path, const char *common_passwords_path, const char *captures_json);

        // execute on a json entry
        result_t execute(void);
        
    private:
        unordered_set<string> secured_urls;
        unordered_set<string> common_passwords;
        string captures_json_path;

        result_t init_string_set_from_file(const char *strings_path, unordered_set<string>& strings_set);
        detection_result_t add_capture(Json::Value entry);
};

#endif /* __RULES_DETECTOR_H__ */
