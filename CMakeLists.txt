cmake_minimum_required(VERSION 2.8)
project(SecGDB)

set(LABHE_DIR ${PROJECT_SOURCE_DIR}/labhe)
set(OBLIVC_DIR ${PROJECT_SOURCE_DIR}/obliv-c)

set (LABHE_LIB ${LABHE_DIR}/build/liblabhe.a)
set (OBLIVC_LIB ${OBLIVC_DIR}/_build/libobliv.a)

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${LABHE_DIR}/include)
include_directories(${OBLIVC_DIR}/src/ext/oblivc)

link_directories(${LABHE_DIR}/build)
link_directories(${LABHE_DIR}/_build)

add_subdirectory (utils)
add_subdirectory (oc)

add_executable(main main.cpp client.cpp server.cpp)

target_link_libraries(main utils oc ${LABHE_LIB} ${OBLIVC_LIB} pthread gcrypt gmpxx gmp crypto)