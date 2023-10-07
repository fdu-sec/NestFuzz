cmake_minimum_required(VERSION 3.4.3)
project(Loop-Handling-Pass)

set(LT_LLVM_INSTALL_DIR "" CACHE PATH "LLVM installation directory")
include_directories(../include)

list(APPEND CMAKE_PREFIX_PATH "${LT_LLVM_INSTALL_DIR}/lib/cmake/llvm/")

find_package(LLVM 10.0.0 REQUIRED CONFIG)

if (LLVM_FOUND)
    message(STATUS "LLVM_VERSION_MAJOR: ${LLVM_VERSION_MAJOR}")
    message(STATUS "LLVM_VERSION_MINOR: ${LLVM_VERSION_MINOR}")
    message(STATUS "LLVM_VERSION_PATCH: ${LLVM_VERSION_PATCH}")
    if (${LLVM_VERSION_MAJOR} LESS 10)
        message(FATAL_ERROR "LLVM version should be 10.0.0+ !")
    endif()
else()
    message(FATAL_ERROR "You haven't install LLVM !")
endif()

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

set(CMAKE_CXX_STANDARD 14 CACHE STRING "")

if(NOT LLVM_ENABLE_RTTI)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()

add_library(LoopHandlingPass MODULE LoopHandlingPass.cpp)
install (TARGETS LoopHandlingPass DESTINATION ${ANGORA_PASS_DIR})

add_library(DFSanPass MODULE DataFlowSanitizer.cpp)
#target_link_libraries(DFSanPass LLVMPassConfig)
install (TARGETS DFSanPass DESTINATION ${ANGORA_PASS_DIR})
