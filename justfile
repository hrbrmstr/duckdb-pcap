# Show the tasks
@default:
  just --list

# build the project
@build:
  VCPKG_TOOLCHAIN_PATH=`pwd`/vcpkg/scripts/buildsystems/vcpkg.cmake BUILD_PPCAP=1 make release
  cp build/release/compile_commands.json .
