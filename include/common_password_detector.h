/**
 * @file common_password_detector.h
 *
 * @author Boaz Lavon
 * @date 10/21
 */
#ifndef __COMMON_PASSWORD_DETECTOR_H__
#define __COMMON_PASSWORD_DETECTOR_H__

#include "json/json.h"
#include "commons.h"
#include "generic_detector.h"

using namespace std;

class CommonPasswordDetector : GenericDetector {
	private:
		unordered_set<string> *secured_hosts;
		unordered_set<string> *common_passwords;

    public:
		CommonPasswordDetector();
    	virtual bool detect(Json::Value& entry);
		void set_secured_hosts(unordered_set<string> *secured_hosts);
		void set_common_passwords(unordered_set<string> *set_common_passwords);
};

#endif /* __COMMON_PASSWORD_DETECTOR_H__ */
