/*
    settings_cli.cpp

    - local MariaDB-backed hub settings administration tool

        v0.0.09:
            - implement list, get, set and check commands
            - reuse Config, Database and canonical hub-setting validation
            - keep database credentials in the protected hub-home option file

    Author: gpt-5.6-sol
    Date: 2026-08-21
*/

// ----------------------------------// DECLARATION //--

#include "settings_cli.hpp"

#include "config.hpp"
#include "database.hpp"

#include <algorithm>
#include <cctype>
#include <exception>
#include <filesystem>
#include <grp.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

namespace dc24h {
namespace {

void usage(std::ostream& output) {
    output
        << "Usage:\n"
        << "  dc24h-settings HUB_HOME list\n"
        << "  dc24h-settings HUB_HOME get KEY\n"
        << "  dc24h-settings HUB_HOME set KEY VALUE\n"
        << "  dc24h-settings HUB_HOME check\n";
}

gid_t dc24h_group_id() {
    const group* service_group = getgrnam("dc24h");
    if (service_group == nullptr) {
        throw std::runtime_error("dc24h system group does not exist");
    }
    return service_group->gr_gid;
}

void require_protected_path(const std::filesystem::path& path,
                            mode_t required_mode,
                            bool directory) {
    struct stat metadata {};
    if (lstat(path.c_str(), &metadata) != 0) {
        throw std::runtime_error("Unable to inspect protected path: " +
                                 path.string());
    }
    if ((directory && !S_ISDIR(metadata.st_mode)) ||
        (!directory && !S_ISREG(metadata.st_mode)) ||
        S_ISLNK(metadata.st_mode)) {
        throw std::runtime_error("Invalid protected path type: " + path.string());
    }
    if (metadata.st_uid != 0U || metadata.st_gid != dc24h_group_id() ||
        (metadata.st_mode & 0777U) != required_mode) {
        throw std::runtime_error(
            "Protected path has unexpected owner, group or mode: " +
            path.string());
    }
}

bool safe_hub_name(std::string_view name) {
    if (name.empty() || name == "." || name == "..") return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char character) {
        return std::isalnum(character) != 0 || character == '.' ||
               character == '-' || character == '_';
    });
}

std::filesystem::path checked_hub_home(std::string_view input) {
    const std::filesystem::path supplied(input);
    if (!supplied.is_absolute()) {
        throw std::runtime_error("HUB_HOME must be an absolute path");
    }
    if (std::filesystem::is_symlink(std::filesystem::symlink_status(supplied))) {
        throw std::runtime_error("HUB_HOME must not be a symbolic link");
    }
    const auto home = std::filesystem::canonical(supplied);
    if (home != supplied.lexically_normal()) {
        throw std::runtime_error("HUB_HOME must not contain traversal or symlinks");
    }
    const std::filesystem::path base("/var/lib/dc24h.eu");
    if (home.parent_path() != base ||
        !safe_hub_name(home.filename().string())) {
        throw std::runtime_error(
            "HUB_HOME must be one safe child of /var/lib/dc24h.eu");
    }
    require_protected_path(home, 0750U, true);
    const auto config_path = home / "dc24h.conf";
    require_protected_path(config_path, 0640U, false);
    return home;
}

std::string canonical_key(std::string_view key) {
    return key == "key.account.password.setup.timeout"
        ? "key.user.password.initial.timeout"
        : std::string(key);
}

std::vector<std::pair<std::string, std::string>> checked_entries(
    Database& database) {
    return database.hub_setting_entries();
}

}  // namespace

int settings_cli_main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        usage(std::cout);
        return 0;
    }
    if (argc < 3) {
        usage(std::cerr);
        return 2;
    }

    try {
        if (geteuid() != 0U) {
            throw std::runtime_error("local settings administration requires root");
        }
        const auto home = checked_hub_home(argv[1]);
        const std::string_view command(argv[2]);
        const auto config = load_config((home / "dc24h.conf").string());
        require_protected_path(config.database_config_path, 0640U, false);
        Database database(config);
        database.connect();

        if (command == "list" && argc == 3) {
            for (const auto& [key, value] : checked_entries(database)) {
                std::cout << key << '=' << value << '\n';
            }
            return 0;
        }
        if (command == "get" && argc == 4) {
            const auto key = canonical_key(argv[3]);
            const auto entries = checked_entries(database);
            const auto found = std::find_if(
                entries.begin(), entries.end(), [&](const auto& entry) {
                    return entry.first == key;
                });
            if (found == entries.end()) {
                std::cerr << "Unknown hub setting: " << key << '\n';
                return 3;
            }
            std::cout << found->first << '=' << found->second << '\n';
            return 0;
        }
        if (command == "set" && argc == 5) {
            const auto key = canonical_key(argv[3]);
            if (!database.set_hub_setting(key, argv[4])) {
                std::cerr << "Invalid hub setting or cross-setting invariant: "
                          << key << '\n';
                return 3;
            }
            const auto entries = checked_entries(database);
            const auto found = std::find_if(
                entries.begin(), entries.end(), [&](const auto& entry) {
                    return entry.first == key;
                });
            if (found == entries.end()) {
                throw std::runtime_error("updated hub setting was not stored");
            }
            std::cout << "updated " << found->first << '=' << found->second
                      << '\n';
            return 0;
        }
        if (command == "check" && argc == 3) {
            const auto entries = checked_entries(database);
            std::cout << "OK: " << entries.size()
                      << " canonical hub settings are valid\n";
            return 0;
        }

        usage(std::cerr);
        return 2;
    } catch (const std::exception& exception) {
        std::cerr << "dc24h-settings: " << exception.what() << '\n';
        return 1;
    }
}

}  // namespace dc24h

int main(int argc, char** argv) {
    return dc24h::settings_cli_main(argc, argv);
}
