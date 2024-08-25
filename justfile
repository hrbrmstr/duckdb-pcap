# Show the tasks
@default
  just --list

# build the project
@build:
  make
  cp build/release/compile_commands.json .
