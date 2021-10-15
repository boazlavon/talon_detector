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
    public:
    	virtual bool detect(Json::Value& entry) = 0;	    
        string extract_password(Json::Value& entry);
        string extract_user(Json::Value& entry);
};

#endif /* __GENERIC_DETECTOR_H__ */
