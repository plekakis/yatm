cmake_minimum_required(VERSION 3.10)

project(yatm_parallel_for)

add_executable(yatm_parallel_for yatm_parallel_for.cpp)

target_link_libraries(yatm_parallel_for PUBLIC SharedSettings)
