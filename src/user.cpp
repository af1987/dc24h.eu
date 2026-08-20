/*
    user.cpp

    v0.0.03:
        - implement numeric user class mapping
        - hash account passwords with PBKDF2-HMAC-SHA256 and random salt
        - add constant-time password hash verification

    Author: gpt-5.6-sol
    Date: 2026-08-19
*/

#include "user.hpp"

#include <gcrypt.h>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace dc24h {
namespace {

constexpr std::size_t salt_size = 16U;
constexpr std::size_t digest_size = 32U;
constexpr unsigned long pbkdf2_iterations = 210000UL;
constexpr std::string_view password_prefix = "pbkdf2-sha256";

void ensure_gcrypt_initialized() {
    static std::once_flag flag;
    std::call_once(flag, [] {
        if (gcry_check_version(nullptr) == nullptr) {
            throw std::runtime_error("libgcrypt initialization failed");
        }
    });
}

char hex_digit(unsigned int value) noexcept {
    return value < 10U ? static_cast<char>('0' + value)
                       : static_cast<char>('a' + (value - 10U));
}

std::string to_hex(const unsigned char* data, std::size_t size) {
    std::string output;
    output.resize(size * 2U);
    for (std::size_t index = 0; index < size; ++index) {
        const auto value = static_cast<unsigned int>(data[index]);
        output[index * 2U] = hex_digit((value >> 4U) & 0x0FU);
        output[index * 2U + 1U] = hex_digit(value & 0x0FU);
    }
    return output;
}

int from_hex_digit(char value) noexcept {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return 10 + value - 'a';
    if (value >= 'A' && value <= 'F') return 10 + value - 'A';
    return -1;
}

std::optional<std::vector<unsigned char>> from_hex(std::string_view value) {
    if (value.size() % 2U != 0U) return std::nullopt;

    std::vector<unsigned char> output(value.size() / 2U);
    for (std::size_t index = 0; index < output.size(); ++index) {
        const int high = from_hex_digit(value[index * 2U]);
        const int low = from_hex_digit(value[index * 2U + 1U]);
        if (high < 0 || low < 0) return std::nullopt;
        output[index] = static_cast<unsigned char>((high << 4) | low);
    }
    return output;
}

bool constant_time_equal(const std::vector<unsigned char>& left,
                         const std::vector<unsigned char>& right) noexcept {
    if (left.size() != right.size()) return false;

    unsigned char difference = 0U;
    for (std::size_t index = 0; index < left.size(); ++index) {
        difference = static_cast<unsigned char>(
            difference | static_cast<unsigned char>(left[index] ^ right[index]));
    }
    return difference == 0U;
}

std::optional<unsigned long> parse_iterations(std::string_view value) noexcept {
    unsigned long parsed = 0UL;
    const auto* first = value.data();
    const auto* last = value.data() + value.size();
    const auto result = std::from_chars(first, last, parsed);
    if (result.ec != std::errc{} || result.ptr != last || parsed == 0UL) {
        return std::nullopt;
    }
    return parsed;
}

std::vector<unsigned char> derive_password(std::string_view password,
                                           const std::vector<unsigned char>& salt,
                                           unsigned long iterations) {
    ensure_gcrypt_initialized();

    std::vector<unsigned char> digest(digest_size);
    const gcry_error_t error =
        gcry_kdf_derive(password.data(),
                        password.size(),
                        GCRY_KDF_PBKDF2,
                        GCRY_MD_SHA256,
                        salt.data(),
                        salt.size(),
                        iterations,
                        digest.size(),
                        digest.data());
    if (error != 0) {
        throw std::runtime_error(
            "PBKDF2 password derivation failed: " +
            std::string(gcry_strerror(error)));
    }
    return digest;
}

}  // namespace

bool is_valid_user_class(std::int16_t value) noexcept {
    return user_class_from_int(value).has_value();
}

std::optional<UserClass> user_class_from_int(std::int16_t value) noexcept {
    switch (value) {
        case -1: return UserClass::hublist_pinger;
        case 0: return UserClass::regular;
        case 1: return UserClass::registered;
        case 2: return UserClass::vip;
        case 3: return UserClass::operator_user;
        case 4: return UserClass::cheef;
        case 5: return UserClass::admin;
        case 10: return UserClass::master;
        default: return std::nullopt;
    }
}

std::string_view user_class_name(UserClass user_class) noexcept {
    switch (user_class) {
        case UserClass::hublist_pinger: return "Hublist pingers";
        case UserClass::regular: return "Regular users";
        case UserClass::registered: return "Registered users";
        case UserClass::vip: return "VIP users";
        case UserClass::operator_user: return "Operator user";
        case UserClass::cheef: return "Cheef user";
        case UserClass::admin: return "Admin user";
        case UserClass::master: return "Master user";
    }
    return "Unknown";
}

std::string hash_password(std::string_view password) {
    if (password.size() < 8U || password.size() > 1024U) {
        throw std::invalid_argument(
            "password length must be between 8 and 1024 UTF-8 bytes");
    }

    ensure_gcrypt_initialized();

    std::array<unsigned char, salt_size> salt{};
    gcry_randomize(salt.data(), salt.size(), GCRY_STRONG_RANDOM);

    const std::vector<unsigned char> salt_vector(salt.begin(), salt.end());
    const auto digest =
        derive_password(password, salt_vector, pbkdf2_iterations);

    return std::string(password_prefix) + "$" +
           std::to_string(pbkdf2_iterations) + "$" +
           to_hex(salt.data(), salt.size()) + "$" +
           to_hex(digest.data(), digest.size());
}

bool verify_password(std::string_view password,
                     std::string_view encoded_hash) noexcept {
    try {
        const auto first = encoded_hash.find('$');
        if (first == std::string_view::npos ||
            encoded_hash.substr(0, first) != password_prefix) {
            return false;
        }

        const auto second = encoded_hash.find('$', first + 1U);
        const auto third = encoded_hash.find('$', second == std::string_view::npos
                                                        ? second
                                                        : second + 1U);
        if (second == std::string_view::npos ||
            third == std::string_view::npos ||
            encoded_hash.find('$', third + 1U) != std::string_view::npos) {
            return false;
        }

        const auto iterations =
            parse_iterations(encoded_hash.substr(first + 1U,
                                                  second - first - 1U));
        const auto salt =
            from_hex(encoded_hash.substr(second + 1U,
                                         third - second - 1U));
        const auto expected = from_hex(encoded_hash.substr(third + 1U));
        if (!iterations.has_value() ||
            !salt.has_value() ||
            !expected.has_value() ||
            salt->size() != salt_size ||
            expected->size() != digest_size) {
            return false;
        }

        const auto actual = derive_password(password, *salt, *iterations);
        return constant_time_equal(actual, *expected);
    } catch (...) {
        return false;
    }
}

}  // namespace dc24h
