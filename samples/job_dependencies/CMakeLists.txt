cmake_minimum_required(VERSION 3.10)

project(yatm_job_dependencies)

add_executable(yatm_job_dependencies yatm_job_dependencies.cpp)

target_link_libraries(yatm_job_dependencies PUBLIC SharedSettings)
