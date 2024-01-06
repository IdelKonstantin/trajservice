#include "common_stuff.h"

int main (int argc, const char** argv) {

    if(!s2::logger::initLogSystem("./", std::string{argv[0]})) {

        std::cerr << "Не удалось инициировать логгер. Выходим" << std::endl;
        return 1;
    }

	httplib::Server svr; 

	LOG_INFO(fastlog::LogEventType::System) << "Запущен сервер расчета поправок";

	svr.Post("/traj_data", s2::httpworker::postMethod);
	svr.Get("/traj_version", s2::httpworker::getMethod);
	svr.listen("0.0.0.0", 8080);
}