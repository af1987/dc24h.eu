/*
    webadmin.cpp

    - HTTP WebAdmin implementation served on the ADC/ADCS hub port

        v0.0.14:
            - multiplex HTTP and ADC from a bounded first-line probe
            - serve a UTF-8 dashboard plus authenticated status/settings APIs
            - enforce loopback policy, bearer authentication and safe headers
            - update only canonical MariaDB-backed hub settings with auditing
            - serialize HTTP lengths independently from the process locale

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

// ----------------------------------// DECLARATION //--

#include "webadmin.hpp"

#include "version.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <locale>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>

namespace dc24h {
namespace {

struct HttpRequest {
    std::string method;
    std::string target;
    std::map<std::string, std::string> headers;
    std::string body;
};

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char character) {
                       return static_cast<char>(std::tolower(character));
                   });
    return value;
}

std::string trim(std::string value) {
    const auto non_space = [](unsigned char character) {
        return !std::isspace(character);
    };
    while (!value.empty() && !non_space(
               static_cast<unsigned char>(value.front()))) {
        value.erase(value.begin());
    }
    while (!value.empty() && !non_space(
               static_cast<unsigned char>(value.back()))) {
        value.pop_back();
    }
    return value;
}

std::optional<std::size_t> content_length(std::string_view request) noexcept {
    const auto header_end = request.find("\r\n\r\n");
    if (header_end == std::string_view::npos) return std::nullopt;
    std::size_t result = 0;
    bool found = false;
    std::size_t cursor = request.find("\r\n") + 2U;
    while (cursor < header_end) {
        const auto line_end = request.find("\r\n", cursor);
        if (line_end == std::string_view::npos || line_end > header_end) {
            return std::nullopt;
        }
        const auto line = request.substr(cursor, line_end - cursor);
        const auto separator = line.find(':');
        if (separator == std::string_view::npos) return std::nullopt;
        auto name = lower_ascii(std::string(line.substr(0, separator)));
        if (name == "content-length") {
            if (found) return std::nullopt;
            auto value = trim(std::string(line.substr(separator + 1U)));
            const auto parsed = std::from_chars(
                value.data(), value.data() + value.size(), result);
            if (value.empty() || parsed.ec != std::errc{} ||
                parsed.ptr != value.data() + value.size()) {
                return std::nullopt;
            }
            found = true;
        }
        cursor = line_end + 2U;
    }
    return result;
}

std::optional<HttpRequest> parse_request(std::string_view wire) {
    const auto header_end = wire.find("\r\n\r\n");
    if (header_end == std::string_view::npos) return std::nullopt;
    const auto first_end = wire.find("\r\n");
    if (first_end == std::string_view::npos || first_end == 0U) {
        return std::nullopt;
    }
    const auto first = wire.substr(0, first_end);
    const auto first_space = first.find(' ');
    const auto second_space = first.find(' ', first_space + 1U);
    if (first_space == std::string_view::npos ||
        second_space == std::string_view::npos ||
        first.substr(second_space + 1U) != "HTTP/1.1") {
        return std::nullopt;
    }

    HttpRequest request;
    request.method = std::string(first.substr(0, first_space));
    request.target = std::string(
        first.substr(first_space + 1U, second_space - first_space - 1U));
    std::size_t cursor = first_end + 2U;
    while (cursor < header_end) {
        const auto line_end = wire.find("\r\n", cursor);
        if (line_end == std::string_view::npos || line_end > header_end) {
            return std::nullopt;
        }
        const auto line = wire.substr(cursor, line_end - cursor);
        const auto separator = line.find(':');
        if (separator == std::string_view::npos || separator == 0U) {
            return std::nullopt;
        }
        auto name = lower_ascii(std::string(line.substr(0, separator)));
        for (const unsigned char character : name) {
            if (!(std::isalnum(character) || character == '-')) {
                return std::nullopt;
            }
        }
        if (request.headers.contains(name)) return std::nullopt;
        request.headers.emplace(
            std::move(name), trim(std::string(line.substr(separator + 1U))));
        cursor = line_end + 2U;
    }
    if (!request.headers.contains("host")) return std::nullopt;
    if (request.headers.contains("transfer-encoding")) return std::nullopt;
    const auto length = content_length(wire);
    if (!length.has_value()) return std::nullopt;
    const auto body_begin = header_end + 4U;
    if (wire.size() != body_begin + *length) return std::nullopt;
    request.body = std::string(wire.substr(body_begin, *length));
    return request;
}

bool constant_time_equal(std::string_view left, std::string_view right) {
    const std::size_t compared = std::max(left.size(), right.size());
    unsigned int difference =
        static_cast<unsigned int>(left.size() ^ right.size());
    for (std::size_t index = 0; index < compared; ++index) {
        const unsigned char l = index < left.size()
            ? static_cast<unsigned char>(left[index]) : 0U;
        const unsigned char r = index < right.size()
            ? static_cast<unsigned char>(right[index]) : 0U;
        difference |= static_cast<unsigned int>(l ^ r);
    }
    return difference == 0U;
}

std::string json_escape(std::string_view value) {
    std::ostringstream output;
    for (const unsigned char character : value) {
        switch (character) {
            case '\\': output << "\\\\"; break;
            case '"': output << "\\\""; break;
            case '\b': output << "\\b"; break;
            case '\f': output << "\\f"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (character < 0x20U) {
                    constexpr std::array<char, 16> hex{
                        '0','1','2','3','4','5','6','7',
                        '8','9','a','b','c','d','e','f'};
                    output << "\\u00" << hex[character >> 4U]
                           << hex[character & 0x0fU];
                } else {
                    output << static_cast<char>(character);
                }
        }
    }
    return output.str();
}

std::string response(int status,
                     std::string_view reason,
                     std::string_view content_type,
                     std::string body,
                     bool secure_transport,
                     bool head_only = false) {
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << "HTTP/1.1 " << status << ' ' << reason << "\r\n"
           << "Content-Type: " << content_type << "\r\n"
           << "Content-Length: " << body.size() << "\r\n"
           << "Cache-Control: no-store\r\n"
           << "Content-Security-Policy: default-src 'none'; "
              "style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
              "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'\r\n"
           << "Referrer-Policy: no-referrer\r\n"
           << "X-Content-Type-Options: nosniff\r\n"
           << "X-Frame-Options: DENY\r\n";
    if (secure_transport) {
        output << "Strict-Transport-Security: max-age=31536000\r\n";
    }
    output << "Connection: close\r\n\r\n";
    if (!head_only) output << body;
    return output.str();
}

std::string json_response(int status,
                          std::string_view reason,
                          std::string body,
                          bool secure_transport) {
    return response(status, reason, "application/json; charset=utf-8",
                    std::move(body), secure_transport);
}

bool loopback_address(std::string_view address) noexcept {
    return address == "::1" || address.starts_with("127.");
}

bool authorized(const HttpRequest& request, std::string_view token) {
    const auto header = request.headers.find("authorization");
    constexpr std::string_view prefix = "Bearer ";
    if (header == request.headers.end() ||
        !std::string_view(header->second).starts_with(prefix)) {
        return false;
    }
    return constant_time_equal(
        std::string_view(header->second).substr(prefix.size()), token);
}

std::optional<std::pair<std::string, std::string>> setting_body(
    std::string_view body) {
    const auto newline = body.find('\n');
    if (newline == std::string_view::npos || newline == 0U ||
        body.find('\n', newline + 1U) !=
            std::string_view::npos) {
        return std::nullopt;
    }
    auto key = std::string(body.substr(0, newline));
    auto value = std::string(body.substr(newline + 1U));
    if (key.size() > 128U || value.size() > 4096U ||
        !std::string_view(key).starts_with("key.") ||
        !std::all_of(key.begin(), key.end(), [](unsigned char character) {
            return (character >= 'a' && character <= 'z') ||
                   (character >= '0' && character <= '9') ||
                   character == '.';
        })) {
        return std::nullopt;
    }
    return std::pair{std::move(key), std::move(value)};
}

const std::string dashboard = R"HTML(<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>dc24h.eu WebAdmin</title><style>
:root{color-scheme:dark;background:#10151c;color:#e8edf2;font:16px system-ui,sans-serif}body{max-width:980px;margin:3rem auto;padding:0 1rem}h1{color:#62d9b3}section{background:#17212b;border:1px solid #314252;border-radius:12px;padding:1rem;margin:1rem 0}input,button{font:inherit;padding:.55rem;border-radius:6px;border:1px solid #52697d;background:#0f1821;color:#fff}input{min-width:18rem}button{cursor:pointer;background:#176b57}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:.5rem;border-bottom:1px solid #314252}.muted{color:#9fb0bf}.error{color:#ff9a9a}</style></head>
<body><h1>dc24h.eu WebAdmin</h1><p class="muted">ADC/ADCS and WebAdmin share the hub port. API access requires the configured bearer token.</p>
<section><label>Bearer token <input id="token" type="password" autocomplete="current-password"></label> <button id="load">Load</button><p id="status"></p></section>
<section><h2>Hub settings</h2><table><thead><tr><th>Key</th><th>Value</th><th></th></tr></thead><tbody id="settings"></tbody></table></section>
<script>'use strict';const q=s=>document.querySelector(s),token=()=>q('#token').value,headers=()=>({Authorization:'Bearer '+token()});
async function load(){try{const s=await fetch('/webadmin/api/v1/status',{headers:headers()});if(!s.ok)throw Error('HTTP '+s.status);const j=await s.json();q('#status').textContent=`${j.release} — ${j.online_clients}/${j.maximum_clients} clients`;const r=await fetch('/webadmin/api/v1/settings',{headers:headers()});if(!r.ok)throw Error('HTTP '+r.status);const a=await r.json(),b=q('#settings');b.textContent='';for(const x of a.settings){const tr=document.createElement('tr'),k=document.createElement('td'),v=document.createElement('td'),c=document.createElement('td'),i=document.createElement('input'),bt=document.createElement('button');k.textContent=x.key;i.value=x.value;bt.textContent='Save';bt.onclick=async()=>{const z=await fetch('/webadmin/api/v1/settings',{method:'PUT',headers:{...headers(),'Content-Type':'text/plain;charset=UTF-8'},body:x.key+'\n'+i.value});if(!z.ok)alert('Update failed: HTTP '+z.status);else load()};v.append(i);c.append(bt);tr.append(k,v,c);b.append(tr)}q('#status').className=''}catch(e){q('#status').textContent=e.message;q('#status').className='error'}}q('#load').onclick=load;</script></body></html>)HTML";

}  // namespace

WebAdmin::WebAdmin(const Config& config) : config_(config) {}

ProtocolProbe WebAdmin::classify_protocol(std::string_view bytes) noexcept {
    constexpr std::array<std::string_view, 5> methods{
        "GET ", "HEAD ", "OPTIONS ", "PUT ", "POST "};
    bool possible_http = false;
    for (const auto method : methods) {
        if (method.starts_with(bytes)) possible_http = true;
        if (bytes.starts_with(method)) {
            const auto end = bytes.find("\r\n");
            if (end == std::string_view::npos) return ProtocolProbe::need_more;
            const auto line = bytes.substr(0, end);
            return line.ends_with(" HTTP/1.1")
                ? ProtocolProbe::http : ProtocolProbe::adc;
        }
    }
    return possible_http ? ProtocolProbe::need_more : ProtocolProbe::adc;
}

HttpRequestState WebAdmin::request_state(std::string_view bytes,
                                         std::size_t maximum_size) noexcept {
    if (bytes.size() > maximum_size) return HttpRequestState::too_large;
    const auto first_line_end = bytes.find("\r\n");
    if ((first_line_end == std::string_view::npos && bytes.size() > 1024U) ||
        (first_line_end != std::string_view::npos &&
         first_line_end > 1024U)) {
        return HttpRequestState::too_large;
    }
    const auto header_end = bytes.find("\r\n\r\n");
    if (header_end == std::string_view::npos) {
        return HttpRequestState::incomplete;
    }
    const auto length = content_length(bytes);
    if (!length.has_value() || *length > maximum_size ||
        header_end + 4U > maximum_size - *length) {
        return HttpRequestState::invalid;
    }
    const auto expected = header_end + 4U + *length;
    if (bytes.size() < expected) return HttpRequestState::incomplete;
    if (bytes.size() > expected) return HttpRequestState::invalid;
    return parse_request(bytes).has_value()
        ? HttpRequestState::complete : HttpRequestState::invalid;
}

std::string WebAdmin::handle(std::string_view wire,
                             std::string_view remote_address,
                             bool secure_transport,
                             const WebAdminRuntime& runtime) const {
    const auto parsed = parse_request(wire);
    if (!parsed.has_value()) {
        return json_response(400, "Bad Request", "{\"error\":\"bad request\"}",
                             secure_transport);
    }
    const auto& request = *parsed;
    const bool head_only = request.method == "HEAD";

    if (!config_.webadmin.enabled) {
        return json_response(404, "Not Found", "{\"error\":\"not found\"}",
                             secure_transport);
    }
    if (config_.webadmin.loopback_only && !loopback_address(remote_address)) {
        return json_response(403, "Forbidden", "{\"error\":\"forbidden\"}",
                             secure_transport);
    }
    if ((request.method == "GET" || head_only) &&
        (request.target == "/" || request.target == "/webadmin" ||
         request.target == "/webadmin/")) {
        return response(200, "OK", "text/html; charset=utf-8", dashboard,
                        secure_transport, head_only);
    }
    if (!authorized(request, config_.webadmin.token)) {
        auto denied = json_response(
            401, "Unauthorized", "{\"error\":\"unauthorized\"}",
            secure_transport);
        const auto separator = denied.find("\r\n\r\n");
        denied.insert(separator, "\r\nWWW-Authenticate: Bearer realm=\"dc24h.eu WebAdmin\"");
        return denied;
    }
    if (request.method == "OPTIONS" &&
        request.target.starts_with("/webadmin/api/")) {
        return response(204, "No Content", "text/plain; charset=utf-8", {},
                        secure_transport);
    }
    if (request.method == "GET" &&
        request.target == "/webadmin/api/v1/status") {
        return json_response(
            200, "OK",
            "{\"program\":\"dc24h.eu\",\"release\":\"" +
                json_escape(release_name()) + "\",\"protocol\":\"ADC\","
                "\"encoding\":\"UTF-8\",\"online_clients\":" +
                std::to_string(runtime.online_clients) +
                ",\"maximum_clients\":" +
                std::to_string(runtime.maximum_clients) + "}",
            secure_transport);
    }
    if (request.method == "GET" &&
        request.target == "/webadmin/api/v1/settings") {
        std::string body = "{\"settings\":[";
        bool first = true;
        for (const auto& [key, value] : runtime.settings()) {
            if (!first) body += ',';
            first = false;
            body += "{\"key\":\"" + json_escape(key) +
                    "\",\"value\":\"" + json_escape(value) + "\"}";
        }
        body += "]}";
        return json_response(200, "OK", std::move(body), secure_transport);
    }
    if (request.method == "PUT" &&
        request.target == "/webadmin/api/v1/settings") {
        const auto setting = setting_body(request.body);
        if (!setting.has_value()) {
            return json_response(400, "Bad Request",
                "{\"error\":\"body must be key newline value\"}",
                secure_transport);
        }
        bool changed = false;
        try {
            changed = runtime.update_setting(setting->first, setting->second);
            runtime.audit(remote_address, setting->first, changed);
        } catch (const std::exception&) {
            runtime.audit(remote_address, setting->first, false);
            return json_response(422, "Unprocessable Content",
                "{\"error\":\"setting rejected\"}", secure_transport);
        }
        if (!changed) {
            return json_response(404, "Not Found",
                "{\"error\":\"unknown setting\"}", secure_transport);
        }
        return json_response(200, "OK", "{\"updated\":true}",
                             secure_transport);
    }
    return json_response(404, "Not Found", "{\"error\":\"not found\"}",
                         secure_transport);
}

}  // namespace dc24h
