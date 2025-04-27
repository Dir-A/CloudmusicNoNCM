# CloudmusicNoNCM
cmake_minimum_required(VERSION 3.25)

# Project
project(CloudmusicNoNCM_Main)

# Load Config
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    include(cmake/ZQFSettings.cmake)
    include(cmake/ZQFPackages.cmake)
endif()

# Source
add_subdirectory("src")

