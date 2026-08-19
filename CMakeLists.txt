# CMakeLists.txt
#
# v0.0.01:
#   - initial C++20 build for dc24h.eu
#   - add MariaDB Connector/C and Threads dependencies
#   - install binary, example configuration and systemd unit
#
# Author: gpt-5.6-sol
# Date: 2026-08-19

cmake_minimum_required(VERSION 3.25)

project(dc24h LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
pkg_check_modules(MARIADB REQUIRED IMPORTED_TARGET libmariadb)

add_executable(dc24h.eu
    src/main.cpp
    src/main.hpp
    src/version.cpp
    src/version.hpp
    src/config.cpp
    src/config.hpp
    src/database.cpp
    src/database.hpp
    src/adc.cpp
    src/adc.hpp
    src/server.cpp
    src/server.hpp
)

target_include_directories(dc24h.eu PRIVATE src)
target_link_libraries(dc24h.eu PRIVATE PkgConfig::MARIADB Threads::Threads)

target_compile_options(dc24h.eu PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)

install(TARGETS dc24h.eu RUNTIME DESTINATION bin)
install(FILES config/dc24h.conf.example
        DESTINATION /etc/dc24h.eu
        RENAME dc24h.conf)
install(FILES deploy/dc24h.service
        DESTINATION /lib/systemd/system)
