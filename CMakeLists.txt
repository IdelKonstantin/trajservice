cmake_minimum_required(VERSION 3.7)

project(traj)

set(compiller_options -Wall -std=c++1z -g -O0)

set(INC_PATH "include")
set(SRC_PATH "src")

file(GLOB HEADERS ${INC_PATH}/*.h)
file(GLOB SOURCES ${SRC_PATH}/*.cpp)

include_directories(${INC_PATH})

############### test ###############
link_directories(${CMAKE_CURRENT_SOURCE_DIR} ../BALLISTIC_SOLVER_CPP11/Libtrajsolv)

add_executable(${PROJECT_NAME}_test
	${SOURCES} 
	${HEADERS}
	main.cpp
	#CFastLog.cpp
	#common_stuff.cpp	
)

#target_include_directories(${PROJECT_NAME}_test SYSTEM PUBLIC .)
target_include_directories(${PROJECT_NAME}_test SYSTEM PUBLIC ../BALLISTIC_SOLVER_CPP11/Libtrajsolv/include)
#target_include_directories(${PROJECT_NAME}_test SYSTEM PUBLIC /usr/include/jsoncpp/)

#target_link_libraries(${PROJECT_NAME}_test jsoncpp)
target_link_libraries(${PROJECT_NAME}_test pthread)
target_link_libraries(${PROJECT_NAME}_test trajsolv)

target_compile_options(${PROJECT_NAME}_test PRIVATE ${compiller_options})
