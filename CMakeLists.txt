cmake_minimum_required(VERSION 3.5)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(BUILD_MAIN_DUCKDB_LIBRARY FALSE)
set(EXTENSION_STATIC_BUILD ON)
set(BUILD_EXTENSIONS_ONLY TRUE)

set(CMAKE_TOOLCHAIN_FILE /root/dev/vcpkg/scripts/buildsystems/vcpkg.cmake
    CACHE STRING "Vcpkg toolchain file")


if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64")
    set(CMAKE_C_COMPILER /usr/bin/gcc)
    set(CMAKE_CXX_COMPILER /usr/bin/g++)
  endif()
endif()

# Set extension name here
set(TARGET_NAME ppcap)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}")

# DuckDB's extension distribution supports vcpkg. As such, dependencies can be added in ./vcpkg.json and then
# used in cmake with find_package. Feel free to remove or replace with other dependencies.
# Detect the operating system

include(${CMAKE_CURRENT_SOURCE_DIR}/FindPCAP.cmake)

find_package(PCAP REQUIRED)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(PCAP_ROOT_DIR "/root/dev/vcpkg/installed/x64-linux")
  include_directories(SYSTEM /root/dev/vcpkg/installed/x64-linux /root/dev/vcpkg/installed/x64-linux/lib /root/dev/vcpkg/installed/x64-linux/include /root/dev/vcpkg/installed/x64-linux/share/openssl)
  set(OPENSSL_ROOT_DIR "/root/dev/vcpkg/installed/x64-linux")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  # set(CMAKE_OSX_ARCHITECTURES "x86_64;arm64" CACHE STRING "Build architectures for Mac OS X" FORCE)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
    set(PCAP_ROOT_DIR "/Users/hrbrmstr/projects/vcpkg/installed/arm64-osx")
  else()
    message(FATAL_ERROR "Unsupported macOS architecture: ${CMAKE_SYSTEM_PROCESSOR}")
    endif()
else()
  message(FATAL_ERROR "Unsupported operating system: ${CMAKE_SYSTEM_NAME}")
endif()

find_package(OpenSSL REQUIRED PATHS ${OPENSSL_ROOT_DIR})

message(STATUS "OPENSSL_FOUND: ${OPENSSL_FOUND}")
message(STATUS "OPENSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OPENSSL_CRYPTO_LIBRARY: ${OPENSSL_CRYPTO_LIBRARY}")
message(STATUS "OPENSSL_SSL_LIBRARY: ${OPENSSL_SSL_LIBRARY}")

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})
include_directories(src/include)

set(EXTENSION_SOURCES src/ppcap_extension.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

target_link_libraries(${EXTENSION_NAME} OpenSSL::SSL OpenSSL::Crypto pcap)
target_link_libraries(${LOADABLE_EXTENSION_NAME} OpenSSL::SSL OpenSSL::Crypto pcap)

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
