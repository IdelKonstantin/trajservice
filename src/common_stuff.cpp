#include "common_stuff.h"

bool s2::logger::initLogSystem(const std::string& loggerDirPath, const std::string& serviceName) {

	bool opened{false};

	if(fastlog::is_opened()) {
		fastlog::close_log();
	}

	try {
		fastlog::initialize(fastlog::GuaranteedLogger{}, loggerDirPath, serviceName, 1, "");
		fastlog::set_log_level(fastlog::LogLevel::INFO);
		fastlog::log_add_tag("");

		opened = fastlog::is_opened();
	}
	catch(const std::bad_alloc& ex) {

		std::cerr << "Не хватает свободной памяти. Причина [" << ex.what() << "]" << std::endl;
		opened = false;
	}

	return opened;
}

Bullet s2::datapreparator::parseForBulletData(const nlohmann::json& bodyJson) const {

	/* Parse for bullet data "Bullet": {"BCG7": 0.247, "V0": 740, "lenght": 33.15, "weight": 185, "diam.": 7.82} */

	auto BCG7 = std::stof(bodyJson["Bullet"]["BCG7"].dump());
	auto V0 = static_cast<uint16_t>(std::stoi(bodyJson["Bullet"]["V0"].dump()));
	auto lenght = std::stof(bodyJson["Bullet"]["lenght"].dump());
	auto weight = static_cast<uint16_t>(std::stoi(bodyJson["Bullet"]["weight"].dump()));
	auto dia = std::stof(bodyJson["Bullet"]["diam."].dump());
	return Bullet{"*", G7, BCG7, 1.0, 1.0, 1.0, V0, lenght, weight, dia, 15, 0.5, USELESS_COMPLEX_DATA};
}

Rifle s2::datapreparator::parseForRifleData(const nlohmann::json& bodyJson) const {

	/* Parse for bullet data "Rifle": {"zero": 100, "scope_height": 8.0, "twist": 12} */

	auto zero = static_cast<uint16_t>(std::stoi(bodyJson["Rifle"]["zero"].dump()));
	auto scope_height = std::stof(bodyJson["Rifle"]["scope_height"].dump());
	auto twist = static_cast<uint16_t>(std::stoi(bodyJson["Rifle"]["twist"].dump())) * 25.4;
	return Rifle{"*", zero, scope_height, (float)twist, RIGHT_TWIST, HERE, 15, 1000, 0.0, POI_UP, 0.0, POI_LEFT};
}

Scope s2::datapreparator::parseForScopeData(const nlohmann::json& bodyJson) const {

	return Scope{"*", MRAD_UNITS, 0.1, 0.1, MIL_DOT};
}

Options s2::datapreparator::parseForOptions(const nlohmann::json& bodyJson) const {

	return Options{OPTION_YES, OPTION_NO, OPTION_NO, OPTION_YES};
}

Inputs s2::datapreparator::parseForInputs(const nlohmann::json& bodyJson) const {
	
	/* Parse for input data "Inputs": {"dist.": 100, "terrain_angle": 0} */

	auto dist = static_cast<uint16_t>(std::stoi(bodyJson["Inputs"]["dist."].dump()));
	auto terrain_angle = static_cast<uint8_t>(std::stoi(bodyJson["Inputs"]["terrain_angle"].dump()));
	auto target_azimuth = static_cast<int16_t>(std::stoi(bodyJson["Inputs"]["target_azimuth"].dump()));
	auto latitude = static_cast<float>(std::stof(bodyJson["Inputs"]["latitude"].dump()));

	return Inputs{dist, terrain_angle, 0.0, target_azimuth, latitude, 0};
}

Meteo s2::datapreparator::parseForMeteoData(const nlohmann::json& bodyJson) const {

	/* Parse for meteo data "Meteo": {"temp.":15,"press.":1000,"humid.":50} */

	auto temp = static_cast<int8_t>(std::stoi(bodyJson["Meteo"]["temp."].dump()));
	auto press = static_cast<uint16_t>(std::stoi(bodyJson["Meteo"]["press."].dump()));
	auto humid = static_cast<uint8_t>(std::stoi(bodyJson["Meteo"]["humid."].dump()));

	windDataArray windArray{};

	for(auto i = 0; i < WIND_GRANULARITY; ++i) {

		auto windDist = static_cast<uint16_t>(std::stoi(bodyJson["Meteo"]["windage"][i]["dist."].dump()));
		auto windSpeed = static_cast<float>(std::stof(bodyJson["Meteo"]["windage"][i]["speed"].dump()));
		auto windDir = static_cast<uint16_t>(std::stoi(bodyJson["Meteo"]["windage"][i]["dir."].dump()));
		auto windIncl = static_cast<float>(std::stof(bodyJson["Meteo"]["windage"][i]["incl."].dump()));

		windArray[i] = {windDist, windSpeed, windDir, windIncl};
	}	
		
	return Meteo{temp, press, humid, USELESS_DATA, USELESS_DATA, USELESS_DATA, COMPLEX_CASE, &windArray};	
}

std::string s2::datapreparator::serializeResult(const Results& results) const {

	nlohmann::json responceJson;

	responceJson["Result"] = {
		{"Vert.", results.vertAngleUnits}, 
		{"Horiz.", results.horizAngleUnits}, 
		{"Deriv.", results.derivAngleUnits},
		{"Time", results.flightTime}
	};

	return responceJson.dump(4).c_str();
}

void s2::httpworker::postMethod(const httplib::Request& req, httplib::Response& res) {

	LOG_INFO(fastlog::LogEventType::System) << "Получен запрос:";
	LOG_INFO(fastlog::LogEventType::System) << "Method: " << req.method;
	LOG_INFO(fastlog::LogEventType::System) << "Path: " << req.path;

	auto bodyJson = nlohmann::json::parse(req.body);
	LOG_INFO(fastlog::LogEventType::System) << "Body: " << bodyJson.dump(4);

	s2::datapreparator dp;
	auto bullet = dp.parseForBulletData(bodyJson);
	auto rifle = dp.parseForRifleData(bodyJson);
	auto scope = dp.parseForScopeData(bodyJson);
	auto meteo = dp.parseForMeteoData(bodyJson);
	auto options = dp.parseForOptions(bodyJson);
	auto inputs = dp.parseForInputs(bodyJson);

	Results results;
	trajectorySolver(&meteo, &bullet, &rifle, &scope, &inputs, &options, OUT &results);

	auto responceString = dp.serializeResult(results);
	LOG_INFO(fastlog::LogEventType::System) << "Отправлен ответ: " << responceString;

	res.set_header("Access-Control-Allow-Origin", "*");
	res.set_header("Content-Type", "application/json");
	res.set_content(responceString.c_str(), "application/json");
}

void s2::httpworker::getMethod(const httplib::Request& req, httplib::Response& res) {

	LOG_INFO(fastlog::LogEventType::System) << "Получен запрос:";
	LOG_INFO(fastlog::LogEventType::System) << "Method: " << req.method;
	LOG_INFO(fastlog::LogEventType::System) << "Path: " << req.path;

	const std::string responceString{std::string("{\"Verison\":\"") + version + std::string("\"}")};
	LOG_INFO(fastlog::LogEventType::System) << "Отправлен ответ: " << responceString;

	res.set_header("Access-Control-Allow-Origin", "*");
	res.set_header("Content-Type", "application/json");
	res.set_content(responceString.c_str(), "application/json");
}