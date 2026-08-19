/*
    adc.cpp

    v0.0.02:
        - implement ADC 1.0.4 PROTOCOL -> IDENTIFY -> NORMAL state validation
        - negotiate BASE plus TIGR and reject sessions without a hash overlap
        - verify TIGR PID/CID during initial BINF and remove PD before forwarding
        - validate sender SID to prevent header spoofing
        - sanitize client IPv4 INF values against the connected peer address
        - route B, D, E and F message types according to ADC headers
        - reject unknown ADC escape sequences and malformed line syntax

    v0.0.01:
        - implement ADC BASE SUP/SID/INF startup response
        - validate all incoming text as UTF-8
        - route basic BINF, BMSG, BSCH and BRES traffic
        - support BQUI disconnect requests

    Author: gpt-5.6-sol
    Date: 2026-08-19
*/

#include "adc.hpp"

#include "hash.hpp"
#include "version.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <sstream>
#include <unordered_map>

namespace dc24h {
namespace {

using Fields = std::vector<std::pair<std::string, std::string>>;

bool is_upper_alpha(char c) noexcept {
    return c >= 'A' && c <= 'Z';
}

bool is_upper_alnum(char c) noexcept {
    return is_upper_alpha(c) || (c >= '0' && c <= '9');
}

bool is_valid_fourcc(std::string_view token) noexcept {
    return token.size() == 4U &&
           (token[0] == 'B' || token[0] == 'C' || token[0] == 'D' ||
            token[0] == 'E' || token[0] == 'F' || token[0] == 'H' ||
            token[0] == 'I' || token[0] == 'U') &&
           is_upper_alpha(token[1]) &&
           is_upper_alnum(token[2]) &&
           is_upper_alnum(token[3]);
}

bool is_valid_sid(std::string_view sid) noexcept {
    return sid.size() == 4U &&
           std::all_of(sid.begin(), sid.end(), [](char c) {
               return (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7');
           });
}

std::optional<std::vector<std::string>> split_tokens(std::string_view line) {
    if (line.empty() || line.front() == ' ' || line.back() == ' ') {
        return std::nullopt;
    }

    std::vector<std::string> tokens;
    std::size_t start = 0;

    while (start < line.size()) {
        const auto separator = line.find(' ', start);
        const auto end = separator == std::string_view::npos
                             ? line.size()
                             : separator;
        if (end == start) return std::nullopt;

        tokens.emplace_back(line.substr(start, end - start));
        if (separator == std::string_view::npos) break;
        start = separator + 1;
    }

    if (tokens.empty() || !is_valid_fourcc(tokens.front())) {
        return std::nullopt;
    }
    return tokens;
}

std::string status(std::string_view code,
                   std::string_view description,
                   std::string_view flag = {}) {
    std::string message = "ISTA ";
    message += code;
    message.push_back(' ');
    message += description;
    if (!flag.empty()) {
        message.push_back(' ');
        message += flag;
    }
    message.push_back('\n');
    return message;
}

bool contains_feature(std::string_view comma_list, std::string_view feature) {
    std::size_t start = 0;
    while (start <= comma_list.size()) {
        const auto comma = comma_list.find(',', start);
        const auto end = comma == std::string_view::npos
                             ? comma_list.size()
                             : comma;
        if (comma_list.substr(start, end - start) == feature) {
            return true;
        }
        if (comma == std::string_view::npos) break;
        start = comma + 1;
    }
    return false;
}

bool supports_feature(const std::vector<std::string>& tokens,
                      std::string_view feature) {
    bool enabled = false;
    for (std::size_t i = 1; i < tokens.size(); ++i) {
        if (tokens[i].size() != 6U) continue;
        if (tokens[i].substr(2) != feature) continue;
        if (tokens[i].starts_with("AD")) enabled = true;
        if (tokens[i].starts_with("RM")) enabled = false;
    }
    return enabled;
}

bool valid_support_tokens(const std::vector<std::string>& tokens) {
    if (tokens.size() < 2U) return false;

    for (std::size_t i = 1; i < tokens.size(); ++i) {
        const auto& token = tokens[i];
        if (token.size() != 6U ||
            (!token.starts_with("AD") && !token.starts_with("RM"))) {
            return false;
        }
        if (!std::all_of(token.begin() + 2, token.end(), [](char c) {
                return is_upper_alnum(c);
            })) {
            return false;
        }
    }
    return true;
}

bool removes_feature(const std::vector<std::string>& tokens,
                     std::string_view feature) {
    for (std::size_t i = 1; i < tokens.size(); ++i) {
        if (tokens[i].size() == 6U &&
            tokens[i].starts_with("RM") &&
            tokens[i].substr(2) == feature) {
            return true;
        }
    }
    return false;
}

bool parse_named_fields(const std::vector<std::string>& tokens,
                        std::size_t start,
                        Fields& fields) {
    for (std::size_t i = start; i < tokens.size(); ++i) {
        const auto& token = tokens[i];
        if (token.size() < 2U ||
            !is_upper_alpha(token[0]) ||
            !is_upper_alnum(token[1])) {
            return false;
        }
        fields.emplace_back(token.substr(0, 2), token.substr(2));
    }
    return true;
}

std::optional<std::string> field_value(const Fields& fields,
                                       std::string_view key) {
    for (auto it = fields.rbegin(); it != fields.rend(); ++it) {
        if (it->first == key) return it->second;
    }
    return std::nullopt;
}

std::string build_binf(std::string_view sid, const Fields& fields) {
    std::string result = "BINF ";
    result += sid;
    for (const auto& [name, value] : fields) {
        if (name == "PD") continue;
        result.push_back(' ');
        result += name;
        result += value;
    }
    result.push_back('\n');
    return result;
}

bool parse_feature_selector(std::string_view selector,
                            std::vector<std::string>& required,
                            std::vector<std::string>& excluded) {
    if (selector.empty() || selector.size() % 5U != 0U) return false;

    for (std::size_t offset = 0; offset < selector.size(); offset += 5U) {
        const char sign = selector[offset];
        if (sign != '+' && sign != '-') return false;

        const auto feature = selector.substr(offset + 1U, 4U);
        if (!std::all_of(feature.begin(), feature.end(), [](char c) {
                return is_upper_alnum(c);
            })) {
            return false;
        }

        if (sign == '+') required.emplace_back(feature);
        else excluded.emplace_back(feature);
    }
    return true;
}

bool has_raw_control(std::string_view line) noexcept {
    for (const unsigned char c : line) {
        if (c < 0x20U || c == 0x7FU) return true;
    }
    return false;
}

}  // namespace

AdcProtocol::AdcProtocol(std::string hub_name, std::string hub_description)
    : hub_name_(std::move(hub_name)),
      hub_description_(std::move(hub_description)) {}

AdcAction AdcProtocol::handle_line(std::string_view line,
                                   std::string_view sid,
                                   std::string_view remote_address,
                                   AdcSession& session) const {
    AdcAction action;

    if (!is_valid_utf8(line) ||
        !has_valid_escapes(line) ||
        has_raw_control(line)) {
        action.direct_messages.emplace_back(
            status("240", "Malformed\\sprotocol\\sline"));
        action.disconnect = true;
        return action;
    }

    const auto maybe_tokens = split_tokens(line);
    if (!maybe_tokens.has_value()) {
        action.direct_messages.emplace_back(
            status("240", "Malformed\\sprotocol\\sline"));
        action.disconnect = true;
        return action;
    }
    const auto& tokens = *maybe_tokens;
    const auto& fourcc = tokens.front();

    if (session.state == AdcState::protocol) {
        if (fourcc != "HSUP") {
            action.direct_messages.emplace_back(
                status("244", "Invalid\\sstate", "FC" + fourcc));
            action.disconnect = true;
            return action;
        }

        if (!valid_support_tokens(tokens)) {
            action.direct_messages.emplace_back(
                status("240", "Malformed\\sSUP"));
            action.disconnect = true;
            return action;
        }

        if (!supports_feature(tokens, "BASE")) {
            action.direct_messages.emplace_back(
                status("245", "Required\\sfeature\\smissing", "FCBASE"));
            action.disconnect = true;
            return action;
        }

        if (!supports_feature(tokens, "TIGR")) {
            action.direct_messages.emplace_back(
                status("247", "No\\shash\\ssupport\\soverlap"));
            action.disconnect = true;
            return action;
        }

        action.direct_messages.emplace_back("ISUP ADTIGR ADBASE\n");
        action.direct_messages.emplace_back("ISID " + std::string(sid) + "\n");
        action.direct_messages.emplace_back(
            "IINF CT32 NI" + escape_adc(hub_name_) +
            " DE" + escape_adc(hub_description_) +
            " VE" + escape_adc(std::string(program_name()) + "/" +
                               std::string(version())) +
            " SUTIGR,BASE\n");
        session.state = AdcState::identify;
        return action;
    }

    if (session.state == AdcState::identify) {
        if (fourcc != "BINF" || tokens.size() < 3U) {
            action.direct_messages.emplace_back(
                status("244", "Invalid\\sstate", "FC" + fourcc));
            action.disconnect = true;
            return action;
        }
        if (!is_valid_sid(tokens[1]) || tokens[1] != sid) {
            action.direct_messages.emplace_back(
                status("240", "Invalid\\ssender\\sSID", "FCBINF"));
            action.disconnect = true;
            return action;
        }

        Fields fields;
        if (!parse_named_fields(tokens, 2U, fields)) {
            action.direct_messages.emplace_back(
                status("243", "Required\\sINF\\sfield\\sbad", "FBBINF"));
            action.disconnect = true;
            return action;
        }

        const auto cid = field_value(fields, "ID");
        const auto pid = field_value(fields, "PD");
        const auto nick = field_value(fields, "NI");
        const auto supported = field_value(fields, "SU");

        if (!cid.has_value()) {
            action.direct_messages.emplace_back(
                status("243", "Required\\sINF\\sfield\\smissing", "FMID"));
            action.disconnect = true;
            return action;
        }
        if (!pid.has_value()) {
            action.direct_messages.emplace_back(
                status("243", "Required\\sINF\\sfield\\smissing", "FMPD"));
            action.disconnect = true;
            return action;
        }
        if (!nick.has_value() || nick->empty()) {
            action.direct_messages.emplace_back(
                status("243", "Required\\sINF\\sfield\\smissing", "FMNI"));
            action.disconnect = true;
            return action;
        }
        if (!supported.has_value() ||
            !contains_feature(*supported, "BASE") ||
            !contains_feature(*supported, "TIGR")) {
            action.direct_messages.emplace_back(
                status("245", "Required\\sfeature\\smissing", "FCBASE"));
            action.disconnect = true;
            return action;
        }
        if (!verify_tiger_pid_cid(*pid, *cid)) {
            action.direct_messages.emplace_back(
                status("227", "Invalid\\sPID", "FBPD"));
            action.disconnect = true;
            return action;
        }

        for (auto& [name, value] : fields) {
            if (name != "I4") continue;
            if (value == "0.0.0.0") {
                value = std::string(remote_address);
            } else if (value != remote_address) {
                action.direct_messages.emplace_back(
                    status("246", "Invalid\\sIP\\ssupplied",
                           "I4" + std::string(remote_address)));
                action.disconnect = true;
                return action;
            }
        }

        session.cid = *cid;
        session.state = AdcState::normal;

        action.inf_update = true;
        action.became_normal = true;
        action.inf_fields = fields;
        action.routed_message = build_binf(sid, fields);
        return action;
    }

    if (fourcc == "HSUP") {
        if (!valid_support_tokens(tokens)) {
            action.direct_messages.emplace_back(
                status("140", "Malformed\\sSUP"));
            return action;
        }
        if (removes_feature(tokens, "BASE") ||
            removes_feature(tokens, "TIGR")) {
            action.direct_messages.emplace_back(
                status("145", "Required\\sfeature\\scannot\\sbe\\sremoved"));
        }
        return action;
    }

    if (fourcc.substr(1) == "QUI") {
        action.disconnect = true;
        return action;
    }

    if (fourcc == "BINF") {
        if (tokens.size() < 3U ||
            !is_valid_sid(tokens[1]) ||
            tokens[1] != sid) {
            action.direct_messages.emplace_back(
                status("240", "Invalid\\ssender\\sSID", "FCBINF"));
            action.disconnect = true;
            return action;
        }

        Fields fields;
        if (!parse_named_fields(tokens, 2U, fields)) {
            action.direct_messages.emplace_back(
                status("143", "Required\\sINF\\sfield\\sbad", "FBBINF"));
            return action;
        }

        if (field_value(fields, "PD").has_value() ||
            field_value(fields, "ID").has_value()) {
            action.direct_messages.emplace_back(
                status("143", "Identity\\sfield\\scannot\\schange", "FBID"));
            return action;
        }

        for (auto& [name, value] : fields) {
            if (name != "I4") continue;
            if (value == "0.0.0.0") {
                value = std::string(remote_address);
            } else if (value != remote_address) {
                action.direct_messages.emplace_back(
                    status("146", "Invalid\\sIP\\ssupplied",
                           "I4" + std::string(remote_address)));
                return action;
            }
        }

        action.inf_update = true;
        action.inf_fields = fields;
        action.route_mode = RouteMode::broadcast;
        action.routed_message = build_binf(sid, fields);
        return action;
    }

    const char type = fourcc[0];

    if (type == 'H') {
        return action;
    }

    if (type == 'B') {
        if (tokens.size() < 2U ||
            !is_valid_sid(tokens[1]) ||
            tokens[1] != sid) {
            action.direct_messages.emplace_back(
                status("240", "Invalid\\ssender\\sSID", "FC" + fourcc));
            action.disconnect = true;
            return action;
        }

        action.route_mode = RouteMode::broadcast;
        action.routed_message = std::string(line) + "\n";
        return action;
    }

    if (type == 'D' || type == 'E') {
        if (tokens.size() < 3U ||
            !is_valid_sid(tokens[1]) ||
            tokens[1] != sid ||
            !is_valid_sid(tokens[2])) {
            action.direct_messages.emplace_back(
                status("240", "Invalid\\smessage\\sheader", "FC" + fourcc));
            action.disconnect = true;
            return action;
        }

        action.route_mode =
            type == 'D' ? RouteMode::direct : RouteMode::echo;
        action.target_sid = tokens[2];
        action.routed_message = std::string(line) + "\n";
        return action;
    }

    if (type == 'F') {
        if (tokens.size() < 3U ||
            !is_valid_sid(tokens[1]) ||
            tokens[1] != sid ||
            !parse_feature_selector(tokens[2],
                                    action.required_features,
                                    action.excluded_features)) {
            action.direct_messages.emplace_back(
                status("240", "Invalid\\sfeature\\sheader", "FC" + fourcc));
            action.disconnect = true;
            return action;
        }

        action.route_mode = RouteMode::feature;
        action.routed_message = std::string(line) + "\n";
        return action;
    }

    return action;
}

bool AdcProtocol::is_valid_utf8(std::string_view text) noexcept {
    const auto* bytes =
        reinterpret_cast<const unsigned char*>(text.data());
    std::size_t i = 0;

    while (i < text.size()) {
        const unsigned char c = bytes[i];
        std::size_t continuation = 0;
        std::uint32_t codepoint = 0;

        if (c <= 0x7FU) {
            ++i;
            continue;
        } else if ((c & 0xE0U) == 0xC0U) {
            continuation = 1;
            codepoint = c & 0x1FU;
            if (codepoint == 0U) return false;
        } else if ((c & 0xF0U) == 0xE0U) {
            continuation = 2;
            codepoint = c & 0x0FU;
        } else if ((c & 0xF8U) == 0xF0U) {
            continuation = 3;
            codepoint = c & 0x07U;
        } else {
            return false;
        }

        if (i + continuation >= text.size()) return false;

        for (std::size_t j = 1; j <= continuation; ++j) {
            const unsigned char cc = bytes[i + j];
            if ((cc & 0xC0U) != 0x80U) return false;
            codepoint = (codepoint << 6U) | (cc & 0x3FU);
        }

        if ((continuation == 1U && codepoint < 0x80U) ||
            (continuation == 2U && codepoint < 0x800U) ||
            (continuation == 3U && codepoint < 0x10000U) ||
            codepoint > 0x10FFFFU ||
            (codepoint >= 0xD800U && codepoint <= 0xDFFFU)) {
            return false;
        }

        i += continuation + 1U;
    }

    return true;
}

bool AdcProtocol::has_valid_escapes(std::string_view text) noexcept {
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] != '\\') continue;
        if (i + 1U >= text.size()) return false;

        const char escaped = text[i + 1U];
        if (escaped != 's' && escaped != 'n' && escaped != '\\') {
            return false;
        }
        ++i;
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
