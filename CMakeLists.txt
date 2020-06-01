cmake_minimum_required(VERSION 3.0)
project(GraphShield)

# configuration
set (CMAKE_CXX_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

# specify security level
option(SL_128 "Using 128-bits secruity level " ON)
if (SL_128 MATCHES ON)
    message("Security level is 128-bits")
    add_definitions(-DSECURITY_LEVEL_128)
else()
    # add_definitions(-DSECURITY_LEVEL_256)
endif()

# local proxy
option(USING_LOCAL_PROXY "Prepare a local proxy")
if (USING_LOCAL_PROXY MATCHES ON)
    message("Local Proxy mode is ${USING_LOCAL_PROXY}")
    add_definitions(-DSEC_GDB_LOCAL_PROXY)
endif()

# specify simple mode (local grable socket)
option(SIMPLE_MODE "Enable simple model")
if (SIMPLE_MODE MATCHES ON)
    message("Simple mode is ${SIMPLE_MODE}")
    add_definitions(-DSEC_GDB_SIMPLE_MODE)
endif()

# encrypt graph or not
option(NO_ENCRYPTION "Not encrypt graph")
if (NO_ENCRYPTION MATCHES ON)
    message("No encryption mode is ${NO_ENCRYPTION}")
    add_definitions(-DSEC_GDB_WITHOUT_ENCRYPTION)
endif()

# import labhe
set(LABHE_DIR ${PROJECT_SOURCE_DIR}/depends/labhe)
include_directories(${LABHE_DIR}/include)
set (LABHE_LIB ${LABHE_DIR}/build/liblabhe.a)

# import obliv-c
set(OBLIVC_DIR ${PROJECT_SOURCE_DIR}/depends/obliv-c)
include_directories(${OBLIVC_DIR}/src/ext/oblivc)
set (OBLIVC_LIB ${OBLIVC_DIR}/_build/libobliv.a)

# import cxxopts
include_directories(${PROJECT_SOURCE_DIR}/depends/cxxopts/include)

# import json
include_directories(${PROJECT_SOURCE_DIR}/depends/json/include)

# include
include_directories(${PROJECT_SOURCE_DIR}/include)

# submodules
add_subdirectory (utils)
add_subdirectory (oc)
add_subdirectory (test)

# build main
add_executable(main main.cpp client.cpp server.cpp proxy.cpp)
# link
target_link_libraries(main utils ${LABHE_LIB} oc ${OBLIVC_LIB} pthread gcrypt gmpxx gmp crypto boost_system boost_filesystem)