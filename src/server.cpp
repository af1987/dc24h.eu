/*
    server.cpp

    v0.0.03:
        - intercept BMSG !set user-management commands before broadcast
        - authorize Admin/Master writes on loopback and first local Master bootstrap
        - return hub-local IMSG command results without exposing passwords
        - retain per-client remote address for the management trust boundary

    v0.0.02:
        - integrate per-connection ADC session state
        - keep merged sanitized INF state for login user-list synchronization
        - route ADC broadcast, direct, echo and feature messages
        - send fatal hub-full status before rejecting excess connections
        - stop accepting CRLF as an implicit ADC line ending

    v0.0.01:
        - implement TCP bind/listen/accept loop on configurable ADC port
        - allocate 20-bit base32 ADC SIDs
        - process newline-framed UTF-8 ADC messages
        - persist connect/disconnect events in MariaDB
        - support systemd-friendly graceful shutdown

    Author: gpt-5.6-sol
    Date: 2026-08-19
*/

#include "server.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace dc24h {

Server::Server(const Config& config,
               const AdcProtocol& protocol,
               Database& database)
    : config_(config),
      protocol_(protocol),
      database_(database),
      user_commands_(database) {}

Server::~Server() {
    disconnect_all();
    if (listen_fd_ >= 0) {
        ::close(listen_fd_);
    }
    join_workers();
}

int Server::run(const std::atomic_bool& stop_requested) {
    listen_fd_ = create_listener();

    std::cout << "dc24h.eu listening on " << config_.listen_address
              << ':' << config_.listen_port << '\n';

    while (!stop_requested.load()) {
        pollfd descriptor{listen_fd_, POLLIN, 0};
        const int poll_result = ::poll(&descriptor, 1, 1000);

        if (poll_result < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(
                "poll failed: " + std::string(std::strerror(errno)));
        }
        if (poll_result == 0) continue;
        if ((descriptor.revents & POLLIN) == 0) continue;

        sockaddr_in peer{};
        socklen_t peer_length = sizeof(peer);
        const int client_fd =
            ::accept(listen_fd_,
                     reinterpret_cast<sockaddr*>(&peer),
                     &peer_length);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            std::cerr << "accept failed: " << std::strerror(errno) << '\n';
            continue;
        }

        char address_buffer[INET_ADDRSTRLEN]{};
        const char* address =
            ::inet_ntop(AF_INET,
                        &peer.sin_addr,
                        address_buffer,
                        sizeof(address_buffer));
        const std::string remote_address =
            address != nullptr ? address : "unknown";

        std::string sid;
        {
            std::lock_guard lock(clients_mutex_);
            if (clients_.size() >= config_.max_clients) {
                send_all(client_fd, "ISTA 211 Hub\\sfull\n");
                ::shutdown(client_fd, SHUT_RDWR);
                ::close(client_fd);
                continue;
            }

            sid = next_sid();
            ClientInfo client;
            client.sid = sid;
            client.remote_address = remote_address;
            clients_.emplace(client_fd, std::move(client));
        }

        try {
            database_.record_event(sid, "connect", remote_address);
        } catch (const std::exception& ex) {
            std::cerr << "database event error: " << ex.what() << '\n';
        }

        std::lock_guard worker_lock(workers_mutex_);
        workers_.emplace_back(
            &Server::client_loop, this, client_fd, sid, remote_address);
    }

    disconnect_all();
    join_workers();
    return 0;
}

int Server::create_listener() const {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        throw std::runtime_error(
            "socket failed: " + std::string(std::strerror(errno)));
    }

    int reuse = 1;
    if (::setsockopt(fd,
                     SOL_SOCKET,
                     SO_REUSEADDR,
                     &reuse,
                     sizeof(reuse)) != 0) {
        ::close(fd);
        throw std::runtime_error("setsockopt(SO_REUSEADDR) failed");
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config_.listen_port);

    if (::inet_pton(AF_INET,
                    config_.listen_address.c_str(),
                    &address.sin_addr) != 1) {
        ::close(fd);
        throw std::runtime_error(
            "listen_address must be a valid IPv4 address");
    }

    if (::bind(fd,
               reinterpret_cast<sockaddr*>(&address),
               sizeof(address)) != 0) {
        const auto error = std::string(std::strerror(errno));
        ::close(fd);
        throw std::runtime_error("bind failed: " + error);
    }

    if (::listen(fd, SOMAXCONN) != 0) {
        const auto error = std::string(std::strerror(errno));
        ::close(fd);
        throw std::runtime_error("listen failed: " + error);
    }

    return fd;
}

void Server::client_loop(int client_fd,
                         std::string sid,
                         std::string remote_address) {
    std::array<char, 8192> buffer{};
    std::string pending;
    pending.reserve(8192);

    AdcSession session;
    bool finished = false;

    while (!finished) {
        const auto received =
            ::recv(client_fd, buffer.data(), buffer.size(), 0);
        if (received == 0) break;
        if (received < 0) {
            if (errno == EINTR) continue;
            break;
        }

        pending.append(buffer.data(), static_cast<std::size_t>(received));

        while (true) {
            const auto newline = pending.find('\n');
            if (newline == std::string::npos) break;

            std::string line = pending.substr(0, newline);
            pending.erase(0, newline + 1U);

            if (line.size() > 65535U) {
                send_all(client_fd, "ISTA 240 Protocol\\sline\\stoo\\slong\n");
                finished = true;
                break;
            }

            const auto action =
                protocol_.handle_line(line, sid, remote_address, session);

            for (const auto& message : action.direct_messages) {
                if (!send_all(client_fd, message)) {
                    finished = true;
                    break;
                }
            }
            if (finished) break;

            if (action.became_normal) {
                if (!finish_identification(client_fd, action.inf_fields)) {
                    finished = true;
                    break;
                }
            } else {
                if (action.inf_update) {
                    apply_inf_update(client_fd, action.inf_fields);
                }
                route_action(client_fd, action);
            }

            if (action.disconnect) {
                finished = true;
                break;
            }
        }

        if (pending.size() > 65535U) {
            send_all(client_fd, "ISTA 240 Protocol\\sline\\stoo\\slong\n");
            finished = true;
        }
    }

    bool was_normal = false;
    {
        std::lock_guard lock(clients_mutex_);
        const auto it = clients_.find(client_fd);
        if (it != clients_.end()) {
            was_normal = it->second.normal;
            clients_.erase(it);
        }
    }

    ::shutdown(client_fd, SHUT_RDWR);
    ::close(client_fd);

    try {
        database_.record_event(sid, "disconnect", remote_address);
    } catch (const std::exception& ex) {
        std::cerr << "database event error: " << ex.what() << '\n';
    }

    if (was_normal) {
        broadcast("IQUI " + sid + "\n");
    }
}

bool Server::finish_identification(
    int client_fd,
    const std::vector<std::pair<std::string, std::string>>& fields) {
    std::vector<std::string> existing_users;
    std::string own_inf;

    {
        std::lock_guard lock(clients_mutex_);
        auto current = clients_.find(client_fd);
        if (current == clients_.end()) return false;

        std::string nick;
        std::string cid;
        for (const auto& [name, value] : fields) {
            if (name == "NI") nick = value;
            if (name == "ID") cid = value;
        }

        for (const auto& [fd, client] : clients_) {
            if (fd == client_fd || !client.normal) continue;

            const auto existing_nick = client.inf_fields.find("NI");
            if (!nick.empty() &&
                existing_nick != client.inf_fields.end() &&
                existing_nick->second == nick) {
                send_all(client_fd, "ISTA 222 Nick\\staken\n");
                return false;
            }

            const auto existing_cid = client.inf_fields.find("ID");
            if (!cid.empty() &&
                existing_cid != client.inf_fields.end() &&
                existing_cid->second == cid) {
                send_all(client_fd, "ISTA 224 CID\\staken\n");
                return false;
            }

            existing_users.push_back(build_current_inf_locked(client));
        }

        for (const auto& [name, value] : fields) {
            if (name == "PD") continue;
            if (value.empty()) current->second.inf_fields.erase(name);
            else current->second.inf_fields[name] = value;
        }

        const auto su = current->second.inf_fields.find("SU");
        current->second.features =
            su == current->second.inf_fields.end()
                ? std::unordered_set<std::string>{}
                : parse_feature_list(su->second);
        current->second.normal = true;
        own_inf = build_current_inf_locked(current->second);
    }

    for (const auto& inf : existing_users) {
        if (!send_all(client_fd, inf)) return false;
    }

    broadcast(own_inf);
    return true;
}

void Server::apply_inf_update(
    int client_fd,
    const std::vector<std::pair<std::string, std::string>>& fields) {
    std::lock_guard lock(clients_mutex_);
    auto current = clients_.find(client_fd);
    if (current == clients_.end()) return;

    for (const auto& [name, value] : fields) {
        if (name == "PD") continue;
        if (value.empty()) current->second.inf_fields.erase(name);
        else current->second.inf_fields[name] = value;
    }

    const auto su = current->second.inf_fields.find("SU");
    current->second.features =
        su == current->second.inf_fields.end()
            ? std::unordered_set<std::string>{}
            : parse_feature_list(su->second);
}

void Server::route_action(int sender_fd, const AdcAction& action) {
    if (handle_user_set_command(sender_fd, action)) {
        return;
    }

    switch (action.route_mode) {
        case RouteMode::none:
            break;
        case RouteMode::broadcast:
            broadcast(action.routed_message);
            break;
        case RouteMode::direct:
            route_direct(sender_fd,
                         action.target_sid,
                         action.routed_message,
                         false);
            break;
        case RouteMode::echo:
            route_direct(sender_fd,
                         action.target_sid,
                         action.routed_message,
                         true);
            break;
        case RouteMode::feature:
            route_feature(action);
            break;
    }
}

bool Server::handle_user_set_command(int sender_fd,
                                     const AdcAction& action) {
    if (action.route_mode != RouteMode::broadcast) {
        return false;
    }

    const auto text = extract_bmsg_text(action.routed_message);
    if (!text.has_value() || !text->starts_with("!set ")) {
        return false;
    }

    std::string encoded_nick;
    std::string remote_address;
    {
        std::lock_guard lock(clients_mutex_);
        const auto sender = clients_.find(sender_fd);
        if (sender == clients_.end() || !sender->second.normal) {
            return true;
        }

        remote_address = sender->second.remote_address;
        const auto nick = sender->second.inf_fields.find("NI");
        if (nick != sender->second.inf_fields.end()) {
            encoded_nick = nick->second;
        }
    }

    const auto nick = decode_adc_value(encoded_nick);
    if (!nick.has_value() || nick->empty()) {
        send_all(sender_fd,
                 "IMSG " +
                     AdcProtocol::escape_adc(
                         "[set] rejected: missing account nickname") +
                     "\n");
        return true;
    }

    if (remote_address != "127.0.0.1") {
        send_all(sender_fd,
                 "IMSG " +
                     AdcProtocol::escape_adc(
                         "[set] rejected: management commands are loopback-only in v0.0.03") +
                     "\n");
        return true;
    }

    try {
        const auto user_class =
            database_.user_class_for_username(*nick);

        bool authorized =
            user_class.has_value() &&
            (*user_class == UserClass::admin ||
             *user_class == UserClass::master);

        if (!authorized && !database_.has_any_enabled_users()) {
            std::string parse_error;
            const auto bootstrap =
                UserCommandProcessor::parse(*text, parse_error);
            authorized =
                bootstrap.has_value() &&
                bootstrap->action == UserSetAction::create_user &&
                bootstrap->user_class == UserClass::master;
        }

        if (!authorized) {
            send_all(sender_fd,
                     "IMSG " +
                         AdcProtocol::escape_adc(
                             "[set] rejected: Admin(5) or Master(10) required") +
                         "\n");
            return true;
        }

        const auto result = user_commands_.execute(*text);
        const std::string response =
            std::string("[set] ") +
            (result.success ? "ok: " : "error: ") +
            result.message;
        send_all(sender_fd,
                 "IMSG " + AdcProtocol::escape_adc(response) + "\n");
    } catch (const std::exception& ex) {
        send_all(sender_fd,
                 "IMSG " +
                     AdcProtocol::escape_adc(
                         std::string("[set] database error: ") + ex.what()) +
                     "\n");
    }

    return true;
}

std::optional<std::string> Server::extract_bmsg_text(
    const std::string& message) {
    if (!message.starts_with("BMSG ")) {
        return std::nullopt;
    }

    const auto sender_end = message.find(' ', 5U);
    if (sender_end == std::string::npos ||
        sender_end + 1U >= message.size()) {
        return std::nullopt;
    }

    auto end = message.find('\n', sender_end + 1U);
    if (end == std::string::npos) end = message.size();

    const auto flag_separator = message.find(' ', sender_end + 1U);
    if (flag_separator != std::string::npos &&
        flag_separator < end) {
        end = flag_separator;
    }

    const auto encoded =
        std::string_view(message).substr(sender_end + 1U,
                                         end - sender_end - 1U);
    return decode_adc_value(encoded);
}

std::optional<std::string> Server::decode_adc_value(
    std::string_view value) {
    std::string output;
    output.reserve(value.size());

    for (std::size_t index = 0; index < value.size(); ++index) {
        if (value[index] != '\\') {
            output.push_back(value[index]);
            continue;
        }

        if (index + 1U >= value.size()) {
            return std::nullopt;
        }

        const char escaped = value[++index];
        switch (escaped) {
            case '\\':
                output.push_back('\\');
                break;
            case 's':
                output.push_back(' ');
                break;
            case 'n':
                output.push_back('\n');
                break;
            default:
                return std::nullopt;
        }
    }

    return output;
}

void Server::broadcast(const std::string& message) {
    std::lock_guard lock(clients_mutex_);
    for (const auto& [fd, client] : clients_) {
        if (!client.normal) continue;
        send_all(fd, message);
    }
}

void Server::route_direct(int sender_fd,
                          std::string_view target_sid,
                          const std::string& message,
                          bool echo_sender) {
    std::lock_guard lock(clients_mutex_);

    int target_fd = -1;
    for (const auto& [fd, client] : clients_) {
        if (client.normal && client.sid == target_sid) {
            target_fd = fd;
            break;
        }
    }

    if (target_fd >= 0) {
        send_all(target_fd, message);
    }
    if (echo_sender && sender_fd != target_fd) {
        const auto sender = clients_.find(sender_fd);
        if (sender != clients_.end() && sender->second.normal) {
            send_all(sender_fd, message);
        }
    }
}

void Server::route_feature(const AdcAction& action) {
    std::lock_guard lock(clients_mutex_);
    for (const auto& [fd, client] : clients_) {
        if (!client.normal) continue;
        if (!feature_match(client,
                           action.required_features,
                           action.excluded_features)) {
            continue;
        }
        send_all(fd, action.routed_message);
    }
}

void Server::disconnect_all() {
    std::lock_guard lock(clients_mutex_);
    for (const auto& [fd, client] : clients_) {
        static_cast<void>(client);
        ::shutdown(fd, SHUT_RDWR);
    }
}

void Server::join_workers() {
    std::vector<std::thread> workers;
    {
        std::lock_guard lock(workers_mutex_);
        workers.swap(workers_);
    }

    for (auto& worker : workers) {
        if (worker.joinable()) worker.join();
    }
}

std::string Server::build_current_inf_locked(
    const ClientInfo& client) const {
    std::string output = "BINF " + client.sid;
    for (const auto& [name, value] : client.inf_fields) {
        if (name == "PD") continue;
        output.push_back(' ');
        output += name;
        output += value;
    }
    output.push_back('\n');
    return output;
}

std::unordered_set<std::string> Server::parse_feature_list(
    const std::string& value) {
    std::unordered_set<std::string> output;
    std::size_t start = 0;

    while (start <= value.size()) {
        const auto comma = value.find(',', start);
        const auto end =
            comma == std::string::npos ? value.size() : comma;
        if (end > start) output.emplace(value.substr(start, end - start));
        if (comma == std::string::npos) break;
        start = comma + 1U;
    }
    return output;
}

bool Server::feature_match(
    const ClientInfo& client,
    const std::vector<std::string>& required,
    const std::vector<std::string>& excluded) {
    for (const auto& feature : required) {
        if (!client.features.contains(feature)) return false;
    }
    for (const auto& feature : excluded) {
        if (client.features.contains(feature)) return false;
    }
    return true;
}

std::string Server::next_sid() {
    constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const std::uint32_t value =
        sid_counter_.fetch_add(1) & 0x000FFFFFU;

    std::string sid(4, 'A');
    std::uint32_t remaining = value;
    for (int index = 3; index >= 0; --index) {
        sid[static_cast<std::size_t>(index)] =
            alphabet[remaining & 0x1FU];
        remaining >>= 5U;
    }
    return sid;
}

bool Server::send_all(int fd, const std::string& message) {
    std::size_t offset = 0;
    while (offset < message.size()) {
        const auto sent =
            ::send(fd,
                   message.data() + offset,
                   message.size() - offset,
                   MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (sent == 0) return false;
        offset += static_cast<std::size_t>(sent);
    }
    return true;
}

}  // namespace dc24h
