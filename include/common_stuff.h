#ifndef _COMMON_STUFF_H_
#define _COMMON_STUFF_H_

#include "httplib.h"
#include "CFastLog.h"
#include "trajectory_solver_API.h"
#include "trajectory_solver.h"
#include "nlohmann.hpp"

namespace s2 {

	const std::string version{"1.0.0"};

	class logger {

		public:
			static bool initLogSystem(const std::string& loggerDirPath, const std::string& serviceName);
	};
	
	class datapreparator {

		public:
			datapreparator() = default;
			Bullet parseForBulletData(const nlohmann::json& bodyJson) const;
			Rifle parseForRifleData(const nlohmann::json& bodyJson) const;
			Scope parseForScopeData(const nlohmann::json& bodyJson) const;
			Meteo parseForMeteoData(const nlohmann::json& bodyJson) const;
			Options parseForOptions(const nlohmann::json& bodyJson) const;
			Inputs parseForInputs(const nlohmann::json& bodyJson) const;
			std::string serializeResult(const Results& results) const;
	};

	class httpworker {

		public:
			static void postMethod(const httplib::Request& req, httplib::Response& res);
			static void getMethod(const httplib::Request& req, httplib::Response& res);
	};
}

#endif /* _COMMON_STUFF_H_ */