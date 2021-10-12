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
        RulesDetector(char *secured_urls_path, char *common_passwords_path);

        // execute on a json entry
        detection_result_t add_capture(int a);
        
    private:
        unordered_set<string> secured_urls;
        unordered_set<string> common_passwords;

        result_t init_string_set_from_file(char *strings_path, unordered_set<string>& strings_set);
};

#endif /* __RULES_DETECTOR_H__ */
