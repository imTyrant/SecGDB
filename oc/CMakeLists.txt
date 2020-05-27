SET (CMAKE_C_COMPILER ${CMAKE_SOURCE_DIR}/obliv-c/bin/oblivcc)

add_library (oc compare.oc)
set_source_files_properties(compare.oc PROPERTIES LANGUAGE C)