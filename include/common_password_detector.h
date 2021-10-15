/**
 * @file common_password_detector.h
 *
 * @author Boaz Lavon
 * @date 10/21
 */
#ifndef __COMMON_PASSWORD_DETECTOR_H__
#define __COMMON_PASSWORD_DETECTOR_H__

#include "json/json.h"

#include "generic_detector.h"

using namespace std;

class CommonPasswordDetector : public GenericDetector {
	private:
		/* this are not smart pointers since there is not need to free those pointers */
		unordered_set<string> *secured_hosts;
		unordered_set<string> *common_passwords;

    public:
		CommonPasswordDetector();
    	virtual bool detect(Json::Value& entry);
		void set_secured_hosts(unordered_set<string> *secured_hosts);
		void set_common_passwords(unordered_set<string> *set_common_passwords);
};

#endif /* __COMMON_PASSWORD_DETECTOR_H__ */
