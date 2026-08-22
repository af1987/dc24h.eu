/*
    config_tests.cpp

    v0.0.14:
        - verify protected WebAdmin token and request-bound configuration

    v0.0.13:
        - verify protocol-flood window and temporary-ban configuration

    v0.0.12:
        - verify TLS/TLS-only, bounded I/O and ADC timeout configuration

    v0.0.11:
        - verify anti-abuse defaults, overrides and invalid limits

    - split runtime/MariaDB configuration tests

        v0.0.09:
            - verify relative database.cnf resolution and legacy compatibility
            - reject mixed, duplicate, incomplete, unsafe and symlinked configs

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

// ----------------------------------// DECLARATION //--

#include "config_tests.hpp"

#include "config.hpp"

#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace dc24h::tests {
namespace {

const std::string runtime_prefix =
    "hub_name=dc24h.eu\n"
    "hub_description=dc24h.eu Direct Connect ADC Hub\n"
    "listen_address=127.0.0.1\n"
    "listen_port=1511\n"
    "max_clients=64\n"
    "locale=en_US.UTF-8\n"
    "dns_lookup=0\n";

const std::string database_options =
    "[client]\n"
    "protocol=tcp\n"
    "host=127.0.0.1\n"
    "port=3306\n"
    "database=dc24h\n"
    "user=dc24h\n"
    "password=0123456789abcdef\n"
    "default-character-set=utf8mb4\n";

void write_file(const std::filesystem::path& path,
                const std::string& content,
                std::filesystem::perms permissions =
                    std::filesystem::perms::owner_read |
                    std::filesystem::perms::owner_write) {
    std::ofstream output(path);
    if (!output) throw std::runtime_error("unable to create test file");
    output << content;
    output.close();
    std::filesystem::permissions(path, permissions);
}

bool throws(const std::function<void()>& operation) {
    try {
        operation();
    } catch (const std::exception&) {
        return true;
    }
    return false;
}

std::string without_option(std::string content, const std::string& key) {
    const auto marker = key + '=';
    const auto position = content.find(marker);
    if (position == std::string::npos) return content;
    const auto line_start = content.rfind('\n', position);
    const auto line_end = content.find('\n', position);
    content.erase(line_start == std::string::npos ? 0U : line_start + 1U,
                  line_end == std::string::npos
                      ? std::string::npos
                      : line_end -
                            (line_start == std::string::npos ? 0U
                                                            : line_start));
    return content;
}

}  // namespace

int run_config_tests() {
    auto pattern =
        (std::filesystem::temp_directory_path() / "dc24h-config-tests-XXXXXX")
            .string();
    std::vector<char> directory_template(pattern.begin(), pattern.end());
    directory_template.push_back('\0');
    const char* created = mkdtemp(directory_template.data());
    if (created == nullptr) {
        throw std::runtime_error("unable to create secure test directory");
    }
    const std::filesystem::path root(created);

    try {
        const auto runtime = root / "dc24h.conf";
        const auto database = root / "database.cnf";
        const auto webadmin_token = root / "webadmin.token";
        write_file(database, database_options);
        write_file(webadmin_token,
                   "0123456789abcdef0123456789abcdef0123456789abcdef\n");
        write_file(runtime, runtime_prefix + "database_config=database.cnf\n");

        const auto split = load_config(runtime.string());
        assert(split.database_config_path ==
               std::filesystem::canonical(database).string());
        assert(split.hub_name == "dc24h.eu");
        assert(split.listen_port == 1511U);
        assert(split.anti_abuse.pwd_tmpban == 900U);
        assert(split.anti_abuse.max_users_from_ip == 10U);
        assert(split.anti_abuse.protocol_flood_limit == 120U);
        assert(!split.webadmin.enabled);

        const auto webadmin_runtime = root / "webadmin.conf";
        write_file(
            webadmin_runtime,
            runtime_prefix +
                "webadmin_enabled=1\n"
                "webadmin_loopback_only=1\n"
                "webadmin_token_file=" + webadmin_token.string() + "\n"
                "webadmin_max_request_size=8192\n"
                "database_config=database.cnf\n");
        const auto webadmin_config = load_config(webadmin_runtime.string());
        assert(webadmin_config.webadmin.enabled);
        assert(webadmin_config.webadmin.loopback_only);
        assert(webadmin_config.webadmin.maximum_request_size == 8192U);
        assert(webadmin_config.webadmin.token.size() == 48U);

        const auto missing_webadmin_token = root / "missing-webadmin.conf";
        write_file(
            missing_webadmin_token,
            runtime_prefix + "webadmin_enabled=1\n"
                "database_config=database.cnf\n");
        assert(throws([&] {
            static_cast<void>(load_config(missing_webadmin_token.string()));
        }));

        const auto small_webadmin_request = root / "small-webadmin.conf";
        write_file(
            small_webadmin_request,
            runtime_prefix + "webadmin_max_request_size=1024\n"
                "database_config=database.cnf\n");
        assert(throws([&] {
            static_cast<void>(load_config(small_webadmin_request.string()));
        }));

        const auto protected_runtime = root / "protected.conf";
        write_file(
            protected_runtime,
            runtime_prefix +
                "pwd_tmpban=120\n"
                "password_failure_limit=4\n"
                "password_failure_window=90\n"
                "max_users_from_ip=8\n"
                "reconnect_min_interval=5\n"
                "clone_detect_count=2\n"
                "clone_det_tban_time=180\n"
                "clone_ip_tban_time=240\n"
                "protocol_flood_limit=50\n"
                "protocol_flood_window=5\n"
                "protocol_flood_tmpban=60\n"
                "database_config=database.cnf\n");
        const auto protected_config = load_config(protected_runtime.string());
        assert(protected_config.anti_abuse.pwd_tmpban == 120U);
        assert(protected_config.anti_abuse.password_failure_limit == 4U);
        assert(protected_config.anti_abuse.max_users_from_ip == 8U);
        assert(protected_config.anti_abuse.clone_detect_count == 2U);
        assert(protected_config.anti_abuse.protocol_flood_limit == 50U);
        assert(protected_config.anti_abuse.protocol_flood_window == 5U);
        assert(protected_config.anti_abuse.protocol_flood_tmpban == 60U);

        const auto certificate = root / "server.crt";
        const auto private_key = root / "server.key";
        write_file(certificate, "test certificate\n");
        write_file(private_key, "test private key\n");
        const auto secure_transport = root / "secure-transport.conf";
        write_file(
            secure_transport,
            runtime_prefix +
                "tls_enabled=1\n"
                "tls_only_mode=1\n"
                "tls_port=1512\n"
                "tls_certificate=" + certificate.string() + "\n"
                "tls_private_key=" + private_key.string() + "\n"
                "tls_min_version=TLS1.3\n"
                "tls_handshake_timeout=9\n"
                "mLineSizeMax=4096\n"
                "max_outbuf_size=32768\n"
                "timeout_key=8\n"
                "timeout_validate_nick=12\n"
                "timeout_login=20\n"
                "timeout_myinfo=6\n"
                "timeout_password=25\n"
                "timeout_general=60\n"
                "database_config=database.cnf\n");
        const auto secure_config = load_config(secure_transport.string());
        assert(secure_config.tls.enabled);
        assert(secure_config.tls.tls_only_mode);
        assert(secure_config.tls.minimum_version == "TLS1.3");
        assert(secure_config.io_limits.mLineSizeMax == 4096U);
        assert(secure_config.io_limits.max_outbuf_size == 32768U);
        assert(secure_config.timeout.Key == 8U);
        assert(secure_config.timeout.MyINFO == 6U);
        assert(secure_config.timeout.Password == 25U);

        const auto invalid_tls_only = root / "invalid-tls-only.conf";
        write_file(
            invalid_tls_only,
            runtime_prefix +
                "tls_only_mode=1\n"
                "database_config=database.cnf\n");
        assert(throws([&] {
            static_cast<void>(load_config(invalid_tls_only.string()));
        }));

        const auto invalid_line_limit = root / "invalid-line-limit.conf";
        write_file(
            invalid_line_limit,
            runtime_prefix +
                "mLineSizeMax=65536\n"
                "database_config=database.cnf\n");
        assert(throws([&] {
            static_cast<void>(load_config(invalid_line_limit.string()));
        }));

        const auto invalid_timeout = root / "invalid-timeout.conf";
        write_file(
            invalid_timeout,
            runtime_prefix +
                "timeout_login=5\n"
                "database_config=database.cnf\n");
        assert(throws([&] {
            static_cast<void>(load_config(invalid_timeout.string()));
        }));

        const auto invalid_protection = root / "invalid-protection.conf";
        write_file(
            invalid_protection,
            runtime_prefix +
                "max_users_from_ip=0\n"
                "database_config=database.cnf\n");
        assert(throws([&] {
            static_cast<void>(load_config(invalid_protection.string()));
        }));

        const auto invalid_flood = root / "invalid-flood.conf";
        write_file(
            invalid_flood,
            runtime_prefix +
                "protocol_flood_limit=1\n"
                "database_config=database.cnf\n");
        assert(throws([&] {
            static_cast<void>(load_config(invalid_flood.string()));
        }));

        const auto absolute_runtime = root / "absolute.conf";
        write_file(
            absolute_runtime,
            runtime_prefix + "database_config=" + database.string() + "\n");
        const auto absolute = load_config(absolute_runtime.string());
        assert(absolute.database_config_path ==
               std::filesystem::canonical(database).string());

        const auto legacy = root / "legacy.conf";
        write_file(
            legacy,
            runtime_prefix +
                "database_host=127.0.0.1\n"
                "database_port=3306\n"
                "database_name=dc24h\n"
                "database_user=dc24h\n"
                "database_password=0123456789abcdef\n");
        const auto inline_config = load_config(legacy.string());
        assert(inline_config.database_config_path.empty());
        assert(inline_config.database_password == "0123456789abcdef");

        const auto mixed = root / "mixed.conf";
        write_file(
            mixed,
            runtime_prefix +
                "database_config=database.cnf\n"
                "database_password=0123456789abcdef\n");
        assert(throws([&] { static_cast<void>(load_config(mixed.string())); }));

        const auto duplicate = root / "duplicate.conf";
        write_file(
            duplicate,
            runtime_prefix +
                "database_config=database.cnf\n"
                "database_config=database.cnf\n");
        assert(throws(
            [&] { static_cast<void>(load_config(duplicate.string())); }));

        const auto incomplete_database = root / "incomplete.cnf";
        write_file(incomplete_database, "[client]\npassword=secret\n");
        const auto incomplete_runtime = root / "incomplete.conf";
        write_file(
            incomplete_runtime,
            runtime_prefix + "database_config=incomplete.cnf\n");
        assert(throws([&] {
            static_cast<void>(load_config(incomplete_runtime.string()));
        }));

        const std::vector<std::string> required_options{
            "protocol", "host", "port", "database", "user", "password",
            "default-character-set"};
        for (std::size_t index = 0; index < required_options.size(); ++index) {
            const auto missing_database =
                root / ("missing-" + std::to_string(index) + ".cnf");
            write_file(
                missing_database,
                without_option(database_options, required_options[index]));
            const auto missing_runtime =
                root / ("missing-" + std::to_string(index) + ".conf");
            write_file(
                missing_runtime,
                runtime_prefix + "database_config=" +
                    missing_database.filename().string() + "\n");
            assert(throws([&] {
                static_cast<void>(load_config(missing_runtime.string()));
            }));
        }

        const std::vector<std::string> invalid_database_options{
            database_options + "unknown=value\n",
            database_options + "[client]\n",
            database_options + "host=127.0.0.2\n",
            without_option(database_options, "protocol") +
                "protocol=socket\n",
            without_option(database_options, "default-character-set") +
                "default-character-set=utf8\n",
            without_option(database_options, "port") + "port=0\n",
            without_option(database_options, "port") + "port=65536\n",
            database_options.substr(database_options.find('\n') + 1U)};
        for (std::size_t index = 0;
             index < invalid_database_options.size();
             ++index) {
            const auto invalid_database =
                root / ("invalid-" + std::to_string(index) + ".cnf");
            write_file(invalid_database, invalid_database_options[index]);
            const auto invalid_runtime =
                root / ("invalid-" + std::to_string(index) + ".conf");
            write_file(
                invalid_runtime,
                runtime_prefix + "database_config=" +
                    invalid_database.filename().string() + "\n");
            assert(throws([&] {
                static_cast<void>(load_config(invalid_runtime.string()));
            }));
        }

        const auto unsafe_database = root / "unsafe.cnf";
        write_file(
            unsafe_database,
            database_options,
            std::filesystem::perms::owner_read |
                std::filesystem::perms::owner_write |
                std::filesystem::perms::group_read |
                std::filesystem::perms::others_read);
        const auto unsafe_runtime = root / "unsafe.conf";
        write_file(
            unsafe_runtime,
            runtime_prefix + "database_config=unsafe.cnf\n");
        assert(throws([&] {
            static_cast<void>(load_config(unsafe_runtime.string()));
        }));

        const auto writable_database = root / "group-writable.cnf";
        write_file(
            writable_database,
            database_options,
            std::filesystem::perms::owner_read |
                std::filesystem::perms::owner_write |
                std::filesystem::perms::group_read |
                std::filesystem::perms::group_write);
        const auto writable_runtime = root / "group-writable.conf";
        write_file(
            writable_runtime,
            runtime_prefix + "database_config=group-writable.cnf\n");
        assert(throws([&] {
            static_cast<void>(load_config(writable_runtime.string()));
        }));

        const auto executable_database = root / "executable.cnf";
        write_file(
            executable_database,
            database_options,
            std::filesystem::perms::owner_read |
                std::filesystem::perms::owner_write |
                std::filesystem::perms::owner_exec);
        const auto executable_runtime = root / "executable.conf";
        write_file(
            executable_runtime,
            runtime_prefix + "database_config=executable.cnf\n");
        assert(throws([&] {
            static_cast<void>(load_config(executable_runtime.string()));
        }));

        const auto linked_database = root / "linked.cnf";
        std::filesystem::create_symlink(database, linked_database);
        const auto linked_runtime = root / "linked.conf";
        write_file(
            linked_runtime,
            runtime_prefix + "database_config=linked.cnf\n");
        assert(throws([&] {
            static_cast<void>(load_config(linked_runtime.string()));
        }));

        const auto escaped_runtime = root / "escaped.conf";
        write_file(
            escaped_runtime,
            runtime_prefix + "database_config=../database.cnf\n");
        assert(throws([&] {
            static_cast<void>(load_config(escaped_runtime.string()));
        }));

        const auto dotted_runtime = root / "dotted.conf";
        write_file(
            dotted_runtime,
            runtime_prefix + "database_config=./database.cnf\n");
        assert(throws([&] {
            static_cast<void>(load_config(dotted_runtime.string()));
        }));
    } catch (...) {
        std::filesystem::remove_all(root);
        throw;
    }

    std::filesystem::remove_all(root);
    return 0;
}

}  // namespace dc24h::tests

int main() {
    return dc24h::tests::run_config_tests();
}
