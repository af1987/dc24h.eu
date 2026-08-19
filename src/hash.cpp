/*
    hash.cpp

    v0.0.02:
        - implement unpadded RFC 4648 Base32 used by ADC identifiers
        - use libgcrypt TIGER1 (canonical Tiger/192 output order)
        - verify ADC CID as Tiger hash of the decoded PID

    Author: gpt-5.6-sol
    Date: 2026-08-19
*/

#include "hash.hpp"

#include <gcrypt.h>

#include <array>
#include <cstdint>
#include <stdexcept>

namespace dc24h {
namespace {

constexpr std::string_view base32_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int base32_value(char c) noexcept {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= '2' && c <= '7') return 26 + (c - '2');
    return -1;
}

void ensure_gcrypt() {
    if (gcry_check_version(nullptr) == nullptr) {
        throw std::runtime_error("libgcrypt initialization failed");
    }
    if (gcry_md_get_algo_dlen(GCRY_MD_TIGER1) != 24U) {
        throw std::runtime_error("libgcrypt TIGER1 is unavailable");
    }
}

}  // namespace

bool is_adc_base32(std::string_view value) noexcept {
    if (value.empty()) return false;
    for (const char c : value) {
        if (base32_value(c) < 0) return false;
    }
    return true;
}

std::vector<unsigned char> decode_adc_base32(std::string_view value) {
    if (!is_adc_base32(value)) {
        throw std::invalid_argument("invalid ADC Base32 value");
    }

    std::vector<unsigned char> output;
    output.reserve((value.size() * 5U) / 8U);

    std::uint32_t accumulator = 0;
    int bits = 0;

    for (const char c : value) {
        accumulator = (accumulator << 5U) |
                      static_cast<std::uint32_t>(base32_value(c));
        bits += 5;

        while (bits >= 8) {
            bits -= 8;
            output.push_back(static_cast<unsigned char>(
                (accumulator >> static_cast<unsigned int>(bits)) & 0xFFU));
        }

        if (bits == 0) {
            accumulator = 0;
        } else {
            accumulator &= (1U << static_cast<unsigned int>(bits)) - 1U;
        }
    }

    if (bits > 0 && accumulator != 0) {
        throw std::invalid_argument("non-zero ADC Base32 padding bits");
    }

    return output;
}

std::string encode_adc_base32(std::span<const unsigned char> value) {
    if (value.empty()) return {};

    std::string output;
    output.reserve((value.size() * 8U + 4U) / 5U);

    std::uint32_t accumulator = 0;
    int bits = 0;

    for (const unsigned char byte : value) {
        accumulator = (accumulator << 8U) | static_cast<std::uint32_t>(byte);
        bits += 8;

        while (bits >= 5) {
            bits -= 5;
            const auto index = static_cast<std::size_t>(
                (accumulator >> static_cast<unsigned int>(bits)) & 0x1FU);
            output.push_back(base32_alphabet[index]);
        }

        if (bits == 0) {
            accumulator = 0;
        } else {
            accumulator &= (1U << static_cast<unsigned int>(bits)) - 1U;
        }
    }

    if (bits > 0) {
        const auto index = static_cast<std::size_t>(
            (accumulator << static_cast<unsigned int>(5 - bits)) & 0x1FU);
        output.push_back(base32_alphabet[index]);
    }

    return output;
}

std::string tiger_cid_from_pid(std::string_view pid_base32) {
    const auto pid = decode_adc_base32(pid_base32);
    if (pid.size() != 24U) {
        throw std::invalid_argument("TIGR PID must decode to 24 bytes");
    }

    ensure_gcrypt();

    std::array<unsigned char, 24> digest{};
    gcry_md_hash_buffer(
        GCRY_MD_TIGER1, digest.data(), pid.data(), pid.size());
    return encode_adc_base32(digest);
}

bool verify_tiger_pid_cid(std::string_view pid_base32,
                          std::string_view cid_base32) noexcept {
    try {
        if (cid_base32.size() != 39U || !is_adc_base32(cid_base32)) {
            return false;
        }
        return tiger_cid_from_pid(pid_base32) == cid_base32;
    } catch (...) {
        return false;
    }
}

}  // namespace dc24h
