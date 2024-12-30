# CloudmusicNoNCM
cmake_minimum_required(VERSION 3.25)

# Project Name
project(CloudmusicNoNCM_Main)

# Load Config
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    include(CMakeMycfg.cmake)
    include(CMakeMypkg.cmake)
endif()

# Source
add_subdirectory(src)

