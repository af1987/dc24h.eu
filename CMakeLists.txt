# CMakeLists.txt
#
# v0.0.10:
#   - raise CMake project version to 0.0.10
#   - build the paired central RBAC module
#   - retain password, moderation and command authorization tests
#
# v0.0.09:
#   - raise CMake project version to 0.0.09
#   - build/install the paired local settings administration tool
#   - add split-config, CLI help, shell syntax and ShellCheck tests
#   - install configuration examples without overwriting an active hub home
#
# v0.0.08:
#   - raise CMake project version to 0.0.08
#   - add paired moderation module to daemon and user tests
#
# v0.0.07:
#   - raise CMake project version to 0.0.07
#   - add paired hub-settings module to daemon and user tests
#
# v0.0.06:
#   - raise CMake project version to 0.0.06
#   - retain Release-enabled ADC and moderation-key tests
#
# v0.0.05:
#   - raise CMake project version to 0.0.05
#   - retain ADC and complete user-key parser test targets
#   - keep assert-based test checks enabled in Release builds
#
# v0.0.04:
#   - raise CMake project version to 0.0.04
#   - retain user/password command and MariaDB test targets
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
# Date: 2026-08-21

cmake_minimum_required(VERSION 3.25)

project(dc24h VERSION 0.0.10 LANGUAGES CXX)

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
    src/rbac.cpp
    src/rbac.hpp
    src/hub_settings.cpp
    src/hub_settings.hpp
    src/moderation.cpp
    src/moderation.hpp
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

add_executable(dc24h-settings
    src/settings_cli.cpp
    src/settings_cli.hpp
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
    src/hub_settings.cpp
    src/hub_settings.hpp
    src/moderation.cpp
    src/moderation.hpp
    src/adc.cpp
    src/adc.hpp
)
target_include_directories(dc24h-settings PRIVATE src)
target_link_libraries(dc24h-settings PRIVATE
    PkgConfig::MARIADB
    PkgConfig::GCRYPT
    Threads::Threads
)
target_compile_options(dc24h-settings PRIVATE ${DC24H_WARNING_FLAGS})

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
    target_compile_options(dc24h_tests PRIVATE
        ${DC24H_WARNING_FLAGS}
        -UNDEBUG
    )
    add_test(NAME adc_protocol_and_tigr COMMAND dc24h_tests)

    add_executable(dc24h_user_tests
        tests/user_commands_tests.cpp
        tests/user_commands_tests.hpp
        src/config.hpp
        src/database.cpp
        src/database.hpp
        src/user.cpp
        src/user.hpp
        src/rbac.cpp
        src/rbac.hpp
        src/adc.cpp
        src/adc.hpp
        src/hash.cpp
        src/hash.hpp
        src/version.cpp
        src/version.hpp
        src/hub_settings.cpp
        src/hub_settings.hpp
        src/moderation.cpp
        src/moderation.hpp
        src/user_commands.cpp
        src/user_commands.hpp
    )
    target_include_directories(dc24h_user_tests PRIVATE src tests)
    target_link_libraries(dc24h_user_tests PRIVATE
        PkgConfig::MARIADB
        PkgConfig::GCRYPT
        Threads::Threads
    )
    target_compile_options(dc24h_user_tests PRIVATE
        ${DC24H_WARNING_FLAGS}
        -UNDEBUG
    )
    add_test(NAME user_classes_and_set_commands COMMAND dc24h_user_tests)

    add_executable(dc24h_config_tests
        tests/config_tests.cpp
        tests/config_tests.hpp
        src/config.cpp
        src/config.hpp
    )
    target_include_directories(dc24h_config_tests PRIVATE src tests)
    target_compile_options(dc24h_config_tests PRIVATE
        ${DC24H_WARNING_FLAGS}
        -UNDEBUG
    )
    add_test(NAME split_runtime_database_config COMMAND dc24h_config_tests)
    add_test(NAME settings_cli_help COMMAND dc24h-settings --help)

    find_program(BASH_EXECUTABLE bash REQUIRED)
    find_program(SHELLCHECK_EXECUTABLE shellcheck REQUIRED)
    add_test(
        NAME administration_script_syntax
        COMMAND ${BASH_EXECUTABLE} -n
            ${CMAKE_SOURCE_DIR}/scripts/install.sh
            ${CMAKE_SOURCE_DIR}/scripts/01-edit-hub-settings.sh
    )
    add_test(
        NAME installer_help
        COMMAND ${CMAKE_SOURCE_DIR}/scripts/install.sh --help
    )
    add_test(
        NAME administration_script_help
        COMMAND ${CMAKE_SOURCE_DIR}/scripts/01-edit-hub-settings.sh --help
    )
    add_test(
        NAME administration_script_shellcheck
        COMMAND ${SHELLCHECK_EXECUTABLE}
            ${CMAKE_SOURCE_DIR}/scripts/install.sh
            ${CMAKE_SOURCE_DIR}/scripts/01-edit-hub-settings.sh
    )
endif()

install(TARGETS dc24h.eu dc24h-settings RUNTIME DESTINATION bin)
install(FILES
        config/dc24h.conf.example
        config/database.cnf.example
        DESTINATION share/dc24h.eu)
install(PROGRAMS scripts/01-edit-hub-settings.sh
        DESTINATION libexec/dc24h.eu)
install(FILES deploy/dc24h.service
        DESTINATION /lib/systemd/system)
