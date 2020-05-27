SET (CMAKE_C_COMPILER ${OBLIVC_DIR}/bin/oblivcc)

add_library (oc compare.oc)
set_source_files_properties(compare.oc PROPERTIES LANGUAGE C)