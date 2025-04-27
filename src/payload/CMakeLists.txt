# CloudmusicNoNCM_Payload
cmake_minimum_required(VERSION 3.25)

# Project
project(CloudmusicNoNCM_Payload)

# Module
add_library(${PROJECT_NAME} MODULE "dllmain.cpp")
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_23)
target_compile_options(${PROJECT_NAME} PRIVATE $<$<OR:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>:/utf-8>)

# Warning
target_compile_options(${PROJECT_NAME} PRIVATE $<$<OR:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>:/W4>)
target_compile_options(${PROJECT_NAME} PRIVATE $<$<OR:$<C_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:GNU>>:-Wall -Wextra>)

# External Libraries
target_link_libraries(${PROJECT_NAME} PRIVATE Zut::ZxHook)