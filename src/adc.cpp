/*
    adc.cpp

    v0.0.01:
        - implement ADC BASE SUP/SID/INF startup response
        - validate all incoming text as UTF-8
        - route basic BINF, BMSG, BSCH and BRES traffic
        - support BQUI disconnect requests

    Author: gpt-5.6-sol
    Date: 2026-08-19
*/

#include "adc.hpp"

#include "version.hpp"

#include <cstdint>

namespace dc24h {

AdcProtocol::AdcProtocol(std::string hub_name, std::string hub_description)
    : hub_name_(std::move(hub_name)), hub_description_(std::move(hub_description)) {}

AdcAction AdcProtocol::handle_line(std::string_view line, std::string_view sid) const {
    AdcAction action;

    if (!is_valid_utf8(line)) {
        action.disconnect = true;
        return action;
    }

    if (line.starts_with("HSUP")) {
        action.direct_messages.emplace_back("ISUP ADBASE\n");
        action.direct_messages.emplace_back("ISID " + std::string(sid) + "\n");
        action.direct_messages.emplace_back(
            "IINF NI" + escape_adc(hub_name_) +
            " DE" + escape_adc(hub_description_) +
            " AP" + escape_adc(program_name()) +
            " VE" + escape_adc(version()) + "\n");
        return action;
    }

    if (line.starts_with("BINF ")) {
        action.broadcast_message = std::string(line) + "\n";
        action.broadcast_mode = BroadcastMode::others;
        return action;
    }

    if (line.starts_with("BMSG ") ||
        line.starts_with("BSCH ") ||
        line.starts_with("BRES ")) {
        action.broadcast_message = std::string(line) + "\n";
        action.broadcast_mode = BroadcastMode::all;
        return action;
    }

    if (line.starts_with("BQUI")) {
        action.disconnect = true;
        return action;
    }

    return action;
}

bool AdcProtocol::is_valid_utf8(std::string_view text) noexcept {
    const auto* bytes = reinterpret_cast<const unsigned char*>(text.data());
    std::size_t i = 0;

    while (i < text.size()) {
        const unsigned char c = bytes[i];
        std::size_t continuation = 0;
        std::uint32_t codepoint = 0;

        if (c <= 0x7F) {
            ++i;
            continue;
        } else if ((c & 0xE0) == 0xC0) {
            continuation = 1;
            codepoint = c & 0x1F;
            if (codepoint == 0) return false;
        } else if ((c & 0xF0) == 0xE0) {
            continuation = 2;
            codepoint = c & 0x0F;
        } else if ((c & 0xF8) == 0xF0) {
            continuation = 3;
            codepoint = c & 0x07;
        } else {
            return false;
        }

        if (i + continuation >= text.size()) {
            return false;
        }

        for (std::size_t j = 1; j <= continuation; ++j) {
            const unsigned char cc = bytes[i + j];
            if ((cc & 0xC0) != 0x80) return false;
            codepoint = (codepoint << 6U) | (cc & 0x3FU);
        }

        if ((continuation == 1 && codepoint < 0x80) ||
            (continuation == 2 && codepoint < 0x800) ||
            (continuation == 3 && codepoint < 0x10000) ||
            codepoint > 0x10FFFF ||
            (codepoint >= 0xD800 && codepoint <= 0xDFFF)) {
            return false;
        }

        i += continuation + 1;
    }

    return true;
}

std::string AdcProtocol::escape_adc(std::string_view value) {
    std::string output;
    output.reserve(value.size());

    for (const char c : value) {
        if (c == '\\') output += "\\\\";
        else if (c == ' ') output += "\\s";
        else if (c == '\n') output += "\\n";
        else output.push_back(c);
    }

    return output;
}

}  // namespace dc24h
