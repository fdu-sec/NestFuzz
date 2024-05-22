cmake_minimum_required(VERSION 3.4.3)
project(Loop-Handling-Pass)

set(LT_LLVM_INSTALL_DIR "" CACHE PATH "LLVM installation directory")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(../include)

list(APPEND CMAKE_PREFIX_PATH "${LT_LLVM_INSTALL_DIR}/lib/cmake/llvm/")

find_package(LLVM 16.0.6 REQUIRED CONFIG)

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
add_definitions(${LLVM_DEFINITIONS})

# set(CMAKE_CXX_STANDARD 14 CACHE STRING "")

if(NOT LLVM_ENABLE_RTTI)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fno-rtti")
endif()

llvm_map_components_to_libnames(llvm_libs support core irreader analysis passes)

add_library(LoopHandlingPass MODULE LoopHandlingPass.cpp)
target_link_libraries(LoopHandlingPass LLVM)
# target_link_libraries(LoopHandlingPass ${llvm_libs})
install (TARGETS LoopHandlingPass DESTINATION ${ANGORA_PASS_DIR})

add_library(DFSanPass MODULE DataFlowSanitizer.cpp)
target_link_libraries(DFSanPass LLVM)
# target_link_libraries(DFSanPass ${llvm_libs})
#target_link_libraries(DFSanPass LLVMPassConfig)
install (TARGETS DFSanPass DESTINATION ${ANGORA_PASS_DIR})
