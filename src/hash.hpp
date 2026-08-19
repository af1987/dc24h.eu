/*
    hash.hpp

    v0.0.02:
        - add strict ADC Base32 encode/decode helpers
        - add TIGR session-hash CID derivation and PID/CID verification

    Author: gpt-5.6-sol
    Date: 2026-08-19
*/

#pragma once

#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace dc24h {

bool is_adc_base32(std::string_view value) noexcept;
std::vector<unsigned char> decode_adc_base32(std::string_view value);
std::string encode_adc_base32(std::span<const unsigned char> value);

std::string tiger_cid_from_pid(std::string_view pid_base32);
bool verify_tiger_pid_cid(std::string_view pid_base32,
                          std::string_view cid_base32) noexcept;

}  // namespace dc24h
