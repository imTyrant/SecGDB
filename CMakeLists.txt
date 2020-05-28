cmake_minimum_required(VERSION 2.8)
project(GraphShield)

# configuration
set (CMAKE_CXX_STANDARD 11)

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
add_executable(main main.cpp client.cpp server.cpp)
# link
target_link_libraries(main utils oc ${LABHE_LIB} ${OBLIVC_LIB} pthread gcrypt gmpxx gmp crypto)