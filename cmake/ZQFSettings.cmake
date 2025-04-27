# OutPath
if (CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}-32/")
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}-32/")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}-32/lib/")
else()
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}-64/")
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}-64/")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}-64/lib/")
endif()

# Compiler && Linker
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    # LTCG
    if (CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS AND MSVC)
        message(WARNING "### CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS is not compatible with CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ###")
    endif()
    cmake_policy(SET CMP0069 NEW) 
    set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT IPO_CHECK_RESULT OUTPUT output)
    if(IPO_CHECK_RESULT)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
    else()
        message(WARNING "LTCG is not supported: ${output}")
    endif()

    # MSVC
    add_compile_options($<$<OR:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>:/Gy>)
    add_compile_options($<$<OR:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>:/Zc:inline>)

    # GNU
    # on linux static link may cause some problems
    if(MINGW AND ZQF_MINGW_STATIC_LINK)
        set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
        add_link_options($<$<OR:$<C_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:GNU>>:-static>)
    endif()

    add_link_options($<$<OR:$<C_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:GNU>>:-Wl,--gc-sections>)
    if(NOT CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
        add_link_options($<$<OR:$<C_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:GNU>>:-s>)
    endif()
    add_compile_options($<$<OR:$<C_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:GNU>>:-ffunction-sections>)
    add_compile_options($<$<OR:$<C_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:GNU>>:-fdata-sections>)

endif()

