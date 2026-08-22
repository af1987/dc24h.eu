/*
    user.hpp

    v0.0.11:
        - make Argon2id the only algorithm used for new password hashes
        - retain explicit legacy hash identification for safe migration

    v0.0.10:
        - define MD5 and PBKDF2-SHA256 password hash algorithms
        - make tagged MD5 the requested default while retaining PBKDF2 verification

    v0.0.03:
        - add numeric user classes for hublist pingers and account roles
        - add canonical class validation and display names
        - add PBKDF2-SHA256 password hashing helpers

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace dc24h {

enum class UserClass : std::int16_t {
    hublist_pinger = -1,
    regular = 0,
    registered = 1,
    vip = 2,
    operator_user = 3,
    cheef = 4,
    admin = 5,
    master = 10
};

enum class PasswordHashAlgorithm {
    argon2id,
    pbkdf2_sha256
};

struct UserAccount {
    std::uint64_t id{0};
    std::string username;
    UserClass user_class{UserClass::regular};
    bool enabled{true};
};

bool is_valid_user_class(std::int16_t value) noexcept;
std::optional<UserClass> user_class_from_int(std::int16_t value) noexcept;
std::string_view user_class_name(UserClass user_class) noexcept;

std::string_view password_hash_algorithm_name(
    PasswordHashAlgorithm algorithm) noexcept;
std::string hash_password(
    std::string_view password,
    PasswordHashAlgorithm algorithm = PasswordHashAlgorithm::argon2id);
bool verify_password(std::string_view password,
                     std::string_view encoded_hash) noexcept;
bool password_hash_needs_upgrade(std::string_view encoded_hash) noexcept;

}  // namespace dc24h
