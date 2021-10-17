/**
 * @file common_password_detector.h
 *
 * @author Boaz Lavon
 * @date 10/21
 */
#ifndef __COMMON_PASSWORD_DETECTOR_H__
#define __COMMON_PASSWORD_DETECTOR_H__

#include "generic_detector.h"

using namespace std;

class CommonPasswordDetector : public GenericDetector {
	shared_ptr<unordered_set<string>> secured_hosts;
	shared_ptr<unordered_set<string>> common_passwords;

    public:
		CommonPasswordDetector(
			shared_ptr<unordered_set<string>> secured_hosts,
			shared_ptr<unordered_set<string>> common_passwords
		) : secured_hosts(secured_hosts), common_passwords(common_passwords) {}

    	virtual bool detect(const Json::Value& entry);
};

#endif /* __COMMON_PASSWORD_DETECTOR_H__ */
