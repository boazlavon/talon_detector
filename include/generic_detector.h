/**
 * @file generic_detector.h
 *
 * @author Boaz Lavon
 * @date 10/21
 */
#ifndef __GENERIC_DETECTOR_H__
#define __GENERIC_DETECTOR_H__

#include "json/json.h"

using namespace std;

class GenericDetector {
    protected:
        string extract_password(const Json::Value& entry);
        string extract_user(const Json::Value& entry);

    public:
        virtual bool detect(const Json::Value& entry) = 0;
};

#endif /* __GENERIC_DETECTOR_H__ */
