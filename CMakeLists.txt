# CMakeLists.txt
#
# v0.0.03:
#   - add user class and protected !set command modules
#   - add account command/password tests
#   - link new tests with MariaDB and libgcrypt
#
# v0.0.02:
#   - add libgcrypt TIGER1 dependency for ADC TIGR session hashing
#   - add hash.cpp/hash.hpp to the daemon
#   - add focused ADC/TIGR unit tests and CTest integration
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
pkg_check_modules(GCRYPT REQUIRED IMPORTED_TARGET libgcrypt)

set(DC24H_WARNING_FLAGS
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)

add_executable(dc24h.eu
    src/main.cpp
    src/main.hpp
    src/version.cpp
    src/version.hpp
    src/config.cpp
    src/config.hpp
    src/database.cpp
    src/database.hpp
    src/hash.cpp
    src/hash.hpp
    src/user.cpp
    src/user.hpp
    src/user_commands.cpp
    src/user_commands.hpp
    src/adc.cpp
    src/adc.hpp
    src/server.cpp
    src/server.hpp
)

target_include_directories(dc24h.eu PRIVATE src)
target_link_libraries(dc24h.eu PRIVATE
    PkgConfig::MARIADB
    PkgConfig::GCRYPT
    Threads::Threads
)
target_compile_options(dc24h.eu PRIVATE ${DC24H_WARNING_FLAGS})

include(CTest)
if(BUILD_TESTING)
    add_executable(dc24h_tests
        tests/adc_tests.cpp
        tests/adc_tests.hpp
        src/version.cpp
        src/version.hpp
        src/hash.cpp
        src/hash.hpp
        src/adc.cpp
        src/adc.hpp
    )
    target_include_directories(dc24h_tests PRIVATE src tests)
    target_link_libraries(dc24h_tests PRIVATE PkgConfig::GCRYPT)
    target_compile_options(dc24h_tests PRIVATE ${DC24H_WARNING_FLAGS})
    add_test(NAME adc_protocol_and_tigr COMMAND dc24h_tests)

    add_executable(dc24h_user_tests
        tests/user_commands_tests.cpp
        tests/user_commands_tests.hpp
        src/config.hpp
        src/database.cpp
        src/database.hpp
        src/user.cpp
        src/user.hpp
        src/user_commands.cpp
        src/user_commands.hpp
    )
    target_include_directories(dc24h_user_tests PRIVATE src tests)
    target_link_libraries(dc24h_user_tests PRIVATE
        PkgConfig::MARIADB
        PkgConfig::GCRYPT
        Threads::Threads
    )
    target_compile_options(dc24h_user_tests PRIVATE ${DC24H_WARNING_FLAGS})
    add_test(NAME user_classes_and_set_commands COMMAND dc24h_user_tests)
endif()

install(TARGETS dc24h.eu RUNTIME DESTINATION bin)
install(FILES config/dc24h.conf.example
        DESTINATION /etc/dc24h.eu
        RENAME dc24h.conf)
install(FILES deploy/dc24h.service
        DESTINATION /lib/systemd/system)
