cmake_minimum_required(VERSION 3.10)

project (yatm)

if( NOT CMAKE_SIZEOF_VOID_P EQUAL 8 )
	message(FATAL_ERROR "Only 64bit configurations are supported!")
endif()

add_library(SharedSettings INTERFACE)

# Platform detection
if (WIN32)
set(MACROS "YATM_WIN64=1")
elseif (UNIX AND NOT APPLE)
find_package(Threads REQUIRED)
target_link_libraries(SharedSettings INTERFACE "-pthread")
set(MACROS "YATM_LINUX=1")
elseif (APPLE)
set(MACROS "YATM_APPLE=1")
endif()

target_compile_definitions(SharedSettings INTERFACE ${MACROS})
target_compile_features(SharedSettings INTERFACE cxx_std_17)
target_include_directories(SharedSettings INTERFACE ${CMAKE_SOURCE_DIR}/include)

add_subdirectory(samples)
