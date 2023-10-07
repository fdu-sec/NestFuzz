
add_executable(TestClang test_clang.c)
set_target_properties(TestClang PROPERTIES OUTPUT_NAME "test-clang")

add_custom_command(TARGET TestClang POST_BUILD
    COMMAND ln -sf "test-clang" "test-clang++")
install (TARGETS TestClang DESTINATION ${ANGORA_BIN_DIR})
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/test-clang++ DESTINATION ${ANGORA_BIN_DIR})
