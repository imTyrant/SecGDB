add_executable(dijestra test_dijestra.cpp)
add_test (
    NAME test_dijestra
    COMMAND dijestra
)

add_executable(dinic test_dinic.cpp)
add_test (
    NAME test_dinic
    COMMAND dinic
)

add_executable(ggm test_ggm.c ${PROJECT_SOURCE_DIR}/utils/ggm.c)
target_link_libraries(ggm crypto m)
add_test (
    NAME test_ggm
    COMMAND ggm
)

# add_subdirectory (oblivc_compare)
# add_subdirectory (oblivc-long)