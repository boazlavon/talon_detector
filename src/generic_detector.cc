/**
 * @file generic_detector.cc
 *
 * @author Boaz Lavon
 
 * @date 10/21 */

#include <iostream>
#include <regex>
#include <unordered_set>
#include "json/json.h"

#include "commons.h"
#include "common_password_detector.h"

using namespace std;

#define PASSWORD_REGEX ("password=(\\w+)")
#define USER_REGEX ("user=(\\w+)")
 
static 
string
extract_content_entry(
    Json::Value& entry,
    string entry_regex
) {
    string result = "";
    smatch match;
    size_t count = 0;

    if (!entry.isMember("content")) {
        return "";
    }

    string content = entry["content"].asString();
    regex password_regex(entry_regex);

    auto content_begin = sregex_iterator(content.begin(), content.end(), password_regex);
    auto content_end   = sregex_iterator();
    count = distance(content_begin, content_end);
    if (count != 1) {
        return "";
    }
    match = (*content_begin);
    result = match.str(1);
    return result;
}

string 
GenericDetector::extract_password(    
    Json::Value& entry
) {
    return extract_content_entry(entry, PASSWORD_REGEX);
}

string 
GenericDetector::extract_user(    
    Json::Value& entry
) {
    return extract_content_entry(entry, USER_REGEX);
}