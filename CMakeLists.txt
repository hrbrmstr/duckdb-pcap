cmake_minimum_required(VERSION 3.5)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(BUILD_MAIN_DUCKDB_LIBRARY FALSE)
set(EXTENSION_STATIC_BUILD ON)
set(BUILD_EXTENSIONS_ONLY TRUE)

set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake
    CACHE STRING "Vcpkg toolchain file")


if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64")
    set(CMAKE_C_COMPILER /usr/bin/gcc)
    set(CMAKE_CXX_COMPILER /usr/bin/g++)
  endif()
endif()

set(TARGET_NAME ppcap)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}")

include(${CMAKE_CURRENT_SOURCE_DIR}/FindPCAP.cmake)

find_package(PCAP REQUIRED)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(PCAP_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/installed/x64-linux)
  include_directories(
    SYSTEM 
    ${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/installed/x64-linux 
    ${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/installed/x64-linux/lib 
    ${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/installed/x64-linux/include 
  )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
    set(PCAP_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}vcpkg/installed/arm64-osx)
  else()
    message(FATAL_ERROR "Unsupported macOS architecture: ${CMAKE_SYSTEM_PROCESSOR}")
    endif()
else()
  message(FATAL_ERROR "Unsupported operating system: ${CMAKE_SYSTEM_NAME}")
endif()

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})
include_directories(src/include)

set(EXTENSION_SOURCES src/ppcap_extension.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

target_link_libraries(${EXTENSION_NAME} pcap)
target_link_libraries(${LOADABLE_EXTENSION_NAME} pcap)

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
