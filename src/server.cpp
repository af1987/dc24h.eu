/*
    server.cpp

    v0.0.12:
        - serve ADC and TLS 1.3 ADCS through bounded transport objects
        - enforce tls_only_mode, ReadLineLocal limits and login/idle timeouts
        - preserve transport identity for duplicated moderation/routing sockets

    v0.0.11:
        - reject temporary bans, excessive per-IP sessions and rapid reconnects
        - apply mAuthIP during account admission
        - activate configurable AP/VE clone detection and disconnect accounting

    v0.0.10:
        - authorize every parsed command through the central RBAC policy
        - deny commands without an explicit permission mapping
        - resolve and enforce active hostname bans at admission

    v0.0.08:
        - enforce persistent kick and ban entries before ADC NORMAL
        - create moderation audit rows before disconnecting matched sessions
        - add private ban creation, listing and revocation execution paths
        - keep socket writes non-blocking and outside shared state locks
        - apply temporary target classes to kick and ban protection

    v0.0.07:
        - enforce class, nickname, IP-binding and interaction settings
        - add +regme, password setup deadlines and account telemetry
        - honor per-account kick-message visibility

    v0.0.06:
        - enforce timed chat, PM, search and download routing restrictions
        - add protected kick and non-punitive disconnect operations
        - filter user visibility, share and ADC operator CT flags

    v0.0.05:
        - execute the complete private key.user administration command set
        - add online IP/hostname, exact-IP, range and subnet queries
        - apply in-memory temporary classes with Admin as the maximum
        - add loopback-only +passwd first-password assignment

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
    Date: 2026-08-22
*/

#include "server.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <ctime>
#include <iostream>
#include <iterator>
#include <stdexcept>

namespace dc24h {
namespace {

std::optional<std::uint32_t> ipv4_host_order(std::string_view text) {
    in_addr address{};
    const std::string input(text);
    if (::inet_pton(AF_INET, input.c_str(), &address) != 1) {
        return std::nullopt;
    }
    return ntohl(address.s_addr);
}

std::string moderation_denial(const ModerationEntry& entry) {
    return "ISTA 230 " + AdcProtocol::escape_adc(
        "Access denied by " + std::string(moderation_action_name(entry.action)) +
        " id=" + std::to_string(entry.id) + " reason=" + entry.reason) + "\n";
}

}  // namespace

Server::Server(const Config& config,
               const AdcProtocol& protocol,
               Database& database)
    : config_(config),
      protocol_(protocol),
      database_(database),
      user_commands_(database),
      anti_abuse_(config.anti_abuse) {
    if (config_.tls.enabled) {
        tls_context_ = std::make_unique<TlsServerContext>(config_.tls);
    }
}

Server::~Server() {
    disconnect_all();
    if (listen_fd_ >= 0) {
        ::close(listen_fd_);
    }
    if (tls_listen_fd_ >= 0) {
        ::close(tls_listen_fd_);
    }
    join_workers();
}

int Server::run(const std::atomic_bool& stop_requested) {
    if (!config_.tls.tls_only_mode) {
        listen_fd_ = create_listener(config_.listen_port);
        std::cout << "dc24h.eu ADC listening on " << config_.listen_address
                  << ':' << config_.listen_port << '\n';
    }
    if (config_.tls.enabled) {
        tls_listen_fd_ = create_listener(config_.tls.port);
        std::cout << "dc24h.eu ADCS listening on " << config_.listen_address
                  << ':' << config_.tls.port << " minimum="
                  << tls_context_->minimum_version() << '\n';
    }

    while (!stop_requested.load()) {
        expire_client_policies();
        std::array<pollfd, 2> descriptors{{
            {listen_fd_,
             static_cast<short>(listen_fd_ >= 0 ? POLLIN : 0), 0},
            {tls_listen_fd_,
             static_cast<short>(tls_listen_fd_ >= 0 ? POLLIN : 0), 0}}};
        const int poll_result = ::poll(
            descriptors.data(), descriptors.size(), 1000);

        if (poll_result < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(
                "poll failed: " + std::string(std::strerror(errno)));
        }
        if (poll_result == 0) continue;
        if ((descriptors[0].revents & POLLIN) != 0) {
            accept_client(listen_fd_, false);
        }
        if ((descriptors[1].revents & POLLIN) != 0) {
            accept_client(tls_listen_fd_, true);
        }
    }

    disconnect_all();
    join_workers();
    return 0;
}

void Server::accept_client(int listener_fd, bool use_tls) {
        if (listener_fd < 0) return;

        sockaddr_in peer{};
        socklen_t peer_length = sizeof(peer);
        const int client_fd =
            ::accept(listener_fd,
                     reinterpret_cast<sockaddr*>(&peer),
                     &peer_length);
        if (client_fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return;
            std::cerr << "accept failed: " << std::strerror(errno) << '\n';
            return;
        }

        std::shared_ptr<SocketTransport> transport;
        try {
            transport = std::make_shared<SocketTransport>(
                client_fd, config_.io_limits);
        } catch (const std::exception& ex) {
            std::cerr << "transport setup failed: " << ex.what() << '\n';
            ::close(client_fd);
            return;
        }

        char address_buffer[INET_ADDRSTRLEN]{};
        const char* address =
            ::inet_ntop(AF_INET,
                        &peer.sin_addr,
                        address_buffer,
                        sizeof(address_buffer));
        const std::string remote_address =
            address != nullptr ? address : "unknown";
        std::string moderation_hostname;

        if (const auto denied = anti_abuse_.AdmitConnection(remote_address);
            denied.has_value()) {
            std::string response = "ISTA 230 " +
                AdcProtocol::escape_adc(denied->reason);
            if (denied->retry_after_seconds > 0U) {
                response += " TL" +
                    std::to_string(denied->retry_after_seconds);
            }
            if (!use_tls) {
                transport->write_all(
                    response + "\n",
                    std::chrono::seconds(config_.timeout.General));
            }
            return;
        }

        try {
            std::optional<ModerationEntry> blocked;
            {
                std::lock_guard moderation_lock(moderation_mutex_);
                if (database_.has_active_hostname_bans()) {
                    moderation_hostname =
                        hostname_for_address(remote_address, true);
                }
                blocked = database_.active_moderation_match(
                    {}, {}, remote_address, std::nullopt,
                    moderation_hostname);
            }
            if (blocked.has_value()) {
                if (!use_tls) {
                    transport->write_all(
                        moderation_denial(*blocked),
                        std::chrono::seconds(config_.timeout.General));
                }
                anti_abuse_.RecordDisconnect(remote_address);
                return;
            }
        } catch (const std::exception& ex) {
            std::cerr << "moderation admission error: " << ex.what() << '\n';
            if (!use_tls) {
                transport->write_all(
                    "ISTA 500 Moderation\\scheck\\sunavailable\n",
                    std::chrono::seconds(config_.timeout.General));
            }
            anti_abuse_.RecordDisconnect(remote_address);
            return;
        }

        std::string sid;
        {
            std::lock_guard lock(clients_mutex_);
            if (clients_.size() >= config_.max_clients) {
                if (!use_tls) {
                    transport->write_all(
                        "ISTA 211 Hub\\sfull\n",
                        std::chrono::seconds(config_.timeout.General));
                }
                anti_abuse_.RecordDisconnect(remote_address);
                return;
            }

            sid = next_sid();
            ClientInfo client;
            client.sid = sid;
            client.remote_address = remote_address;
            client.moderation_hostname = moderation_hostname;
            clients_.emplace(client_fd, std::move(client));
        }
        {
            std::lock_guard lock(transports_mutex_);
            transports_.emplace(client_fd, transport);
        }

        try {
            database_.record_event(sid, "connect", remote_address);
        } catch (const std::exception& ex) {
            std::cerr << "database event error: " << ex.what() << '\n';
        }

        std::lock_guard worker_lock(workers_mutex_);
        workers_.emplace_back(
            &Server::client_loop, this, client_fd, sid, remote_address,
            use_tls, std::move(transport));
}

int Server::create_listener(std::uint16_t port) const {
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
    address.sin_port = htons(port);

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
                         std::string remote_address,
                         bool use_tls,
                         std::shared_ptr<SocketTransport> transport) {
    std::array<char, 8192> buffer{};
    BoundedLineReader reader(config_.io_limits.mLineSizeMax);

    AdcSession session;
    bool finished = false;
    auto connection_started = std::chrono::steady_clock::now();
    auto phase_started = connection_started;
    auto last_activity = connection_started;

    if (use_tls &&
        !transport->AcceptTls(
            *tls_context_,
            std::chrono::seconds(config_.tls.handshake_timeout_seconds))) {
        finished = true;
    }
    if (!finished && use_tls) {
        connection_started = std::chrono::steady_clock::now();
        phase_started = connection_started;
        last_activity = connection_started;
    }

    while (!finished) {
        const auto now = std::chrono::steady_clock::now();
        std::uint32_t phase_limit = config_.timeout.General;
        if (session.state == AdcState::protocol) {
            phase_limit = config_.timeout.Key;
        } else if (session.state == AdcState::identify) {
            phase_limit = config_.timeout.ValidateNick;
        }
        if ((session.state != AdcState::normal &&
             now - connection_started >=
                 std::chrono::seconds(config_.timeout.Login)) ||
            (session.state != AdcState::normal &&
             now - phase_started >= std::chrono::seconds(phase_limit)) ||
            (session.state == AdcState::normal &&
             now - last_activity >=
                 std::chrono::seconds(config_.timeout.General))) {
            send_all(client_fd, "ISTA 230 Session\\stimeout\n");
            break;
        }

        pollfd descriptor{client_fd, POLLIN, 0};
        const int poll_result = transport->has_pending_input()
            ? 1
            : ::poll(&descriptor, 1, 1000);
        if (poll_result == 0) continue;
        if (poll_result < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) break;
        if (!transport->has_pending_input() &&
            (descriptor.revents & POLLIN) == 0) continue;

        const auto received = transport->read_some(
            buffer.data(), buffer.size());
        if (received == 0) break;
        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            break;
        }
        last_activity = std::chrono::steady_clock::now();

        auto read_result = reader.ReadLineLocal(std::string_view(
            buffer.data(), static_cast<std::size_t>(received)));
        if (read_result.status == ReadLineStatus::overflow) {
            send_all(client_fd, "ISTA 240 Protocol\\sline\\stoo\\slong\n");
            finished = true;
            break;
        }

        for (const auto& line : read_result.lines) {
            const auto previous_state = session.state;
            const bool is_myinfo =
                line.size() >= 4U && line.substr(1U, 3U) == "INF";
            const auto operation_started = std::chrono::steady_clock::now();

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

            if (is_myinfo &&
                std::chrono::steady_clock::now() - operation_started >=
                    std::chrono::seconds(config_.timeout.MyINFO)) {
                send_all(client_fd, "ISTA 230 MyINFO\\stimeout\n");
                finished = true;
                break;
            }

            if (action.disconnect) {
                finished = true;
                break;
            }
            if (session.state != previous_state) {
                phase_started = std::chrono::steady_clock::now();
            }
        }
    }

    bool was_normal = false;
    std::optional<std::string> disconnected_username;
    std::string clone_fingerprint;
    {
        std::lock_guard lock(clients_mutex_);
        const auto it = clients_.find(client_fd);
        if (it != clients_.end()) {
            was_normal = it->second.normal;
            disconnected_username = client_username(it->second);
            clone_fingerprint = it->second.clone_fingerprint;
            clients_.erase(it);
        }
    }

    {
        std::lock_guard lock(transports_mutex_);
        transports_.erase(client_fd);
    }
    transport->shutdown();
    anti_abuse_.RecordDisconnect(remote_address, clone_fingerprint);

    try {
        database_.record_event(sid, "disconnect", remote_address);
        if (was_normal && disconnected_username.has_value()) {
            database_.record_account_logout(*disconnected_username);
        }
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
    std::unique_lock moderation_lock(moderation_mutex_);
    std::vector<std::string> existing_users;
    std::string encoded_nick;
    std::string cid;
    std::optional<std::uint64_t> share_size;
    for (const auto& [name, value] : fields) {
        if (name == "NI") encoded_nick = value;
        if (name == "ID") cid = value;
        if (name == "SS") {
            std::uint64_t parsed_share = 0;
            const auto parsed = std::from_chars(
                value.data(), value.data() + value.size(), parsed_share);
            if (parsed.ec == std::errc{} &&
                parsed.ptr == value.data() + value.size()) {
                share_size = parsed_share;
            }
        }
    }
    const auto decoded_nick = decode_adc_value(encoded_nick);
    RuntimeUserPolicy policy;
    HubSettings hub_settings;
    std::string remote_address;
    std::string moderation_hostname;
    bool registered_account = false;
    {
        std::lock_guard lock(clients_mutex_);
        const auto current = clients_.find(client_fd);
        if (current == clients_.end()) return false;
        remote_address = current->second.remote_address;
        moderation_hostname = current->second.moderation_hostname;
    }
    try {
        hub_settings = database_.hub_settings();
        if (!decoded_nick.has_value() || decoded_nick->empty()) {
            send_all(client_fd, "ISTA 223 Nick\\srequired\n");
            return false;
        }
        if (moderation_hostname.empty() &&
            database_.has_active_hostname_bans()) {
            moderation_hostname = hostname_for_address(remote_address, true);
        }
        std::string nickname_error;
        if (!nickname_allowed(*decoded_nick, hub_settings, nickname_error)) {
            send_all(client_fd, "ISTA 223 " +
                AdcProtocol::escape_adc(nickname_error) + "\n");
            return false;
        }
        const auto blocked = database_.active_moderation_match(
            *decoded_nick, cid, remote_address, share_size,
            moderation_hostname);
        if (blocked.has_value()) {
            send_all(client_fd, moderation_denial(*blocked));
            return false;
        }
        policy = database_.runtime_policy(*decoded_nick);
        registered_account = policy.registered;
        if (policy.registered && !policy.enabled) {
            send_all(client_fd, "ISTA 226 Account\\sdisabled\n");
            return false;
        }
        if (!mAuthIP(policy.auth_ip, remote_address)) {
            send_all(client_fd, "ISTA 227 Account\\sIP\\smismatch\n");
            return false;
        }
        if (static_cast<std::int16_t>(policy.user_class) <
            hub_settings.minimum_use_hub) {
            send_all(client_fd, "ISTA 230 User\\sclass\\sbelow\\shub\\sminimum\n");
            return false;
        }
    } catch (const std::exception& ex) {
        std::cerr << "database policy error: " << ex.what() << '\n';
        send_all(client_fd, "ISTA 500 Database\\spolicy\\serror\n");
        return false;
    }

    std::string clone_fingerprint;
    for (const auto& [name, value] : fields) {
        if (name == "AP") clone_fingerprint += "AP=" + value + ";";
        if (name == "VE") clone_fingerprint += "VE=" + value + ";";
    }
    if (!clone_fingerprint.empty() &&
        anti_abuse_.CheckUserClone(remote_address, clone_fingerprint)) {
        send_all(client_fd, "ISTA 230 Clone\\sdetection\\slimit\\sexceeded\n");
        return false;
    }
    if (!clone_fingerprint.empty()) {
        std::lock_guard lock(clients_mutex_);
        const auto current = clients_.find(client_fd);
        if (current == clients_.end()) return false;
        current->second.clone_fingerprint = clone_fingerprint;
    }

    {
        std::lock_guard lock(clients_mutex_);
        auto current = clients_.find(client_fd);
        if (current == clients_.end()) return false;

        std::string session_cid;
        for (const auto& [name, value] : fields) {
            if (name == "ID") session_cid = value;
        }

        for (const auto& [fd, client] : clients_) {
            if (fd == client_fd || !client.normal) continue;

            const auto existing_nick = client.inf_fields.find("NI");
            if (decoded_nick.has_value() &&
                existing_nick != client.inf_fields.end()) {
                const auto existing_decoded =
                    decode_adc_value(existing_nick->second);
                const ModerationTarget nickname_target{
                    ModerationTargetKind::nickname, *decoded_nick, {}};
                if (existing_decoded.has_value() &&
                    moderation_target_matches(
                        nickname_target,
                        *existing_decoded,
                        {},
                        {},
                        std::nullopt)) {
                    send_all(client_fd, "ISTA 222 Nick\\staken\n");
                    return false;
                }
            }

            const auto existing_cid = client.inf_fields.find("ID");
            if (!session_cid.empty() &&
                existing_cid != client.inf_fields.end() &&
                existing_cid->second == session_cid) {
                send_all(client_fd, "ISTA 224 CID\\staken\n");
                return false;
            }

            const auto visible_inf = build_current_inf_locked(
                client, policy.user_class, false);
            if (!visible_inf.empty()) existing_users.push_back(visible_inf);
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
        current->second.policy = std::move(policy);
        if (current->second.policy.password_change_required) {
            const auto password_timeout = std::min(
                hub_settings.password_initial_timeout,
                config_.timeout.Password);
            current->second.password_deadline =
                static_cast<std::int64_t>(std::time(nullptr)) +
                static_cast<std::int64_t>(password_timeout);
        }
    }
    moderation_lock.unlock();

    if (decoded_nick.has_value() && registered_account) {
        try {
            database_.record_account_login(*decoded_nick, remote_address);
        } catch (const std::exception& ex) {
            std::cerr << "account login telemetry error: " << ex.what() << '\n';
        }
    }

    for (const auto& inf : existing_users) {
        if (!send_all(client_fd, inf)) return false;
    }

    broadcast_current_inf(client_fd);
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
    if (!enforce_sender_policy(sender_fd, action)) return;
    if (handle_opchat_command(sender_fd, action)) return;
    if (action.inf_update && action.route_mode == RouteMode::broadcast) {
        broadcast_current_inf(sender_fd);
        return;
    }

    switch (action.route_mode) {
        case RouteMode::none:
            break;
        case RouteMode::broadcast:
            broadcast_from(sender_fd, action.routed_message);
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
            route_feature(sender_fd, action);
            break;
    }
}

bool Server::handle_opchat_command(int sender_fd,
                                   const AdcAction& action) {
    if (action.route_mode != RouteMode::broadcast) return false;
    const auto text = extract_bmsg_text(action.routed_message);
    if (!text.has_value() || !text->starts_with("!opchat ")) return false;
    const auto message = text->substr(8U);
    if (message.empty()) {
        send_all(sender_fd, "IMSG [OPChat]\\smessage\\srequired\n");
        return true;
    }

    bool sender_allowed = false;
    std::string response;
    std::vector<int> sockets;
    {
        std::lock_guard lock(clients_mutex_);
        const auto sender = clients_.find(sender_fd);
        if (sender == clients_.end()) return true;
        sender_allowed =
            static_cast<std::int16_t>(sender->second.policy.user_class) >= 3 ||
            has_active_policy(sender->second, "opchat");
        if (sender_allowed) {
            const auto nick = client_username(sender->second);
            response = "[OPChat] " +
                (nick.has_value() ? *nick : sender->second.sid) + ": " + message;
            sockets.reserve(clients_.size());
            for (const auto& [fd, client] : clients_) {
                if (!client.normal) continue;
                if (static_cast<std::int16_t>(client.policy.user_class) >= 3 ||
                    has_active_policy(client, "opchat")) {
                    const int socket = ::dup(fd);
                    if (socket >= 0) sockets.push_back(socket);
                }
            }
        }
    }
    if (!sender_allowed) {
        send_all(sender_fd, "IMSG [OPChat]\\saccess\\sdenied\n");
        return true;
    }
    const auto response_message =
        "IMSG " + AdcProtocol::escape_adc(response) + "\n";
    for (const int socket : sockets) {
        send_all(socket, response_message);
        ::close(socket);
    }
    return true;
}

bool Server::enforce_sender_policy(int sender_fd,
                                   const AdcAction& action) {
    if (action.routed_message.size() < 4U) return true;

    ClientInfo sender;
    {
        std::lock_guard lock(clients_mutex_);
        const auto found = clients_.find(sender_fd);
        if (found == clients_.end()) return false;
        sender = found->second;
    }

    const std::string_view fourcc(action.routed_message.data(), 4U);
    UserClass sender_class = sender.policy.user_class;
    const auto sender_username = client_username(sender);
    if (sender_username.has_value()) {
        const auto temporary = temporary_class_for(*sender_username);
        if (temporary.has_value()) sender_class = *temporary;
    }
    std::string restriction;
    if (fourcc == "BMSG" &&
        (has_active_policy(sender, "gag") ||
         has_active_policy(sender, "no_chat"))) {
        restriction = "public chat is restricted";
    } else if ((fourcc == "DMSG" || fourcc == "EMSG") &&
               (has_active_policy(sender, "no_chat") ||
                has_active_policy(sender, "no_pm"))) {
        restriction = "private messages are restricted";
    } else if ((fourcc.substr(1) == "SCH") &&
               has_active_policy(sender, "no_search")) {
        restriction = "search is restricted";
    } else if ((fourcc.substr(1) == "CTM" || fourcc.substr(1) == "RCM") &&
               has_active_policy(sender, "no_download")) {
        restriction = "downloads are restricted";
    }

    if (restriction.empty() && action.route_mode != RouteMode::broadcast &&
        !action.target_sid.empty() &&
        (fourcc == "DMSG" || fourcc == "EMSG" ||
         fourcc.substr(1) == "CTM" || fourcc.substr(1) == "RCM")) {
        UserClass target_class = UserClass::regular;
        std::optional<std::string> target_username;
        bool target_found = false;
        {
            std::lock_guard lock(clients_mutex_);
            for (const auto& [fd, client] : clients_) {
                static_cast<void>(fd);
                if (client.normal && client.sid == action.target_sid) {
                    target_class = client.policy.user_class;
                    target_username = client_username(client);
                    target_found = true;
                    break;
                }
            }
        }
        if (target_found) {
            if (target_username.has_value()) {
                const auto temporary = temporary_class_for(*target_username);
                if (temporary.has_value()) target_class = *temporary;
            }
            try {
                const auto settings = database_.hub_settings();
                const auto difference =
                    (fourcc == "DMSG" || fourcc == "EMSG")
                        ? settings.pm_class_difference
                        : settings.download_class_difference;
                if (static_cast<std::int16_t>(target_class) >
                    static_cast<std::int16_t>(sender_class) +
                        difference) {
                    restriction = (fourcc == "DMSG" || fourcc == "EMSG")
                        ? "target class cannot be contacted by private message"
                        : "target class does not permit this download request";
                }
            } catch (const std::exception& ex) {
                std::cerr << "hub setting enforcement error: " << ex.what() << '\n';
                restriction = "hub permission settings are unavailable";
            }
        }
    }

    if (restriction.empty()) return true;
    send_all(sender_fd,
             "IMSG " + AdcProtocol::escape_adc(
                 "[restriction] " + restriction) + "\n");
    return false;
}

bool Server::handle_user_set_command(int sender_fd,
                                     const AdcAction& action) {
    if (action.route_mode != RouteMode::broadcast) {
        return false;
    }

    const auto text = extract_bmsg_text(action.routed_message);
    if (!text.has_value() ||
        (!text->starts_with("!set ") && !text->starts_with("+passwd ") &&
         !text->starts_with("+regme "))) {
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

    const bool self_service = text->starts_with("+passwd ") ||
        text->starts_with("+regme ");
    if (!self_service && remote_address != "127.0.0.1") {
        send_all(sender_fd,
                 "IMSG " +
                     AdcProtocol::escape_adc(
                         "[user] rejected: management commands are loopback-only until ADC VERIFY is available") +
                     "\n");
        return true;
    }

    try {
        std::string parse_error;
        auto parsed = UserCommandProcessor::parse(*text, parse_error);
        if (!parsed.has_value()) {
            send_all(sender_fd,
                     "IMSG " + AdcProtocol::escape_adc(
                         "[user] error: " + parse_error) + "\n");
            return true;
        }

        const bool parsed_self_service =
            parsed->action == UserSetAction::self_register ||
            parsed->action == UserSetAction::self_add_password ||
            parsed->action == UserSetAction::set_self_visibility;
        if (parsed_self_service) {
            const auto decision = authorize_action(
                UserClass::regular, parsed->action);
            if (!decision.allowed) {
                send_all(sender_fd,
                         "IMSG " + AdcProtocol::escape_adc(
                             "[authorization] rejected: " +
                             std::string(decision.reason)) + "\n");
                return true;
            }
        }

        const auto hub_settings = database_.hub_settings();
        if ((parsed->action == UserSetAction::kick_user ||
             parsed->action == UserSetAction::create_ban) &&
            parsed->duration_seconds >
                hub_settings.maximum_temporary_ban_seconds) {
            send_all(sender_fd,
                     "IMSG " + AdcProtocol::escape_adc(
                         "[moderation] error: duration exceeds key.bans") +
                     "\n");
            return true;
        }
        if (!parsed->password.empty() &&
            parsed->password.size() < hub_settings.password_minimum_length) {
            send_all(sender_fd,
                     "IMSG " + AdcProtocol::escape_adc(
                         "[user] error: password is shorter than the configured minimum") +
                     "\n");
            return true;
        }

        if (parsed->action == UserSetAction::self_register) {
            if (hub_settings.autoreg_class < 0) {
                send_all(sender_fd,
                         "IMSG [regme]\\serror:\\sauto-registration\\sis\\sdisabled\n");
                return true;
            }
            const auto existing = database_.runtime_policy(*nick);
            if (existing.registered) {
                send_all(sender_fd,
                         "IMSG [regme]\\serror:\\saccount\\salready\\sexists\n");
                return true;
            }
            if (!nickname_has_prefix(*nick,
                                     hub_settings.nick_prefix_autoreg,
                                     hub_settings.nick_prefix_nocase)) {
                send_all(sender_fd,
                         "IMSG [regme]\\serror:\\sauto-registration\\sprefix\\srequired\n");
                return true;
            }

            std::uint64_t share = 0;
            {
                std::lock_guard lock(clients_mutex_);
                const auto sender = clients_.find(sender_fd);
                if (sender != clients_.end()) {
                    const auto field = sender->second.inf_fields.find("SS");
                    if (field != sender->second.inf_fields.end()) {
                        const auto conversion = std::from_chars(
                            field->second.data(),
                            field->second.data() + field->second.size(),
                            share);
                        if (conversion.ec != std::errc{} ||
                            conversion.ptr != field->second.data() +
                                field->second.size()) share = 0;
                    }
                }
            }
            std::uint64_t minimum_share =
                hub_settings.autoreg_minimum_share_registered;
            if (hub_settings.autoreg_class == 2) {
                minimum_share = hub_settings.autoreg_minimum_share_vip;
            } else if (hub_settings.autoreg_class == 3) {
                minimum_share = hub_settings.autoreg_minimum_share_operator;
            }
            if (share < minimum_share) {
                send_all(sender_fd,
                         "IMSG [regme]\\serror:\\sminimum\\sshare\\snot\\smet\n");
                return true;
            }
            const auto autoreg_class = user_class_from_int(
                hub_settings.autoreg_class);
            if (!autoreg_class.has_value()) {
                send_all(sender_fd,
                         "IMSG [regme]\\serror:\\sinvalid\\sconfigured\\sclass\n");
                return true;
            }
            parsed->username = *nick;
            parsed->actor_username = *nick;
            parsed->user_class = *autoreg_class;
            const auto result = user_commands_.execute(*parsed);
            if (result.success) {
                refresh_client_policy(*nick);
                database_.record_account_login(*nick, remote_address);
                std::lock_guard lock(clients_mutex_);
                const auto sender = clients_.find(sender_fd);
                if (sender != clients_.end()) sender->second.password_deadline = 0;
            }
            const std::string response = std::string("[regme] ") +
                (result.success ? "ok: " : "error: ") + result.message;
            send_all(sender_fd,
                     "IMSG " + AdcProtocol::escape_adc(response) + "\n");
            return true;
        }

        if (parsed->action == UserSetAction::self_add_password) {
            parsed->username = *nick;
            const auto result = user_commands_.execute(*parsed);
            if (result.success) {
                refresh_client_policy(*nick);
                std::lock_guard lock(clients_mutex_);
                const auto sender = clients_.find(sender_fd);
                if (sender != clients_.end()) sender->second.password_deadline = 0;
            }
            const std::string response = std::string("[passwd] ") +
                (result.success ? "ok: " : "error: ") + result.message;
            send_all(sender_fd,
                     "IMSG " + AdcProtocol::escape_adc(response) + "\n");
            return true;
        }

        if (parsed->action == UserSetAction::set_self_visibility) {
            parsed->username = *nick;
            const auto account = database_.runtime_policy(*nick);
            if (!account.registered || !account.enabled) {
                send_all(sender_fd,
                         "IMSG " + AdcProtocol::escape_adc(
                             "[user] error: enabled registered account required") +
                         "\n");
                return true;
            }
            const auto result = user_commands_.execute(*parsed);
            if (result.success) refresh_client_policy(*nick);
            const std::string response = std::string("[visibility] ") +
                (result.success ? "ok: " : "error: ") + result.message;
            send_all(sender_fd,
                     "IMSG " + AdcProtocol::escape_adc(response) + "\n");
            return true;
        }

        const auto user_class =
            database_.user_class_for_username(*nick);

        const auto actor_policy = database_.runtime_policy(*nick);
        const auto actor_has_policy = [&](std::string_view key) {
            for (const auto& policy : actor_policy.timed_policies) {
                if (policy.policy_key == key &&
                    policy.expires_at > static_cast<std::int64_t>(std::time(nullptr))) {
                    return true;
                }
            }
            return false;
        };

        const auto temporary_class = temporary_class_for(*nick);

        const auto effective_class = temporary_class.has_value()
            ? temporary_class
            : user_class;
        const auto effective_value = effective_class.has_value()
            ? static_cast<std::int16_t>(*effective_class)
            : static_cast<std::int16_t>(-1);
        AuthorizationDecision authorization;
        if (user_class.has_value() && effective_class.has_value()) {
            authorization = authorize_action(
                *effective_class, parsed->action);
        }
        bool authorized = authorization.allowed;

        if (parsed->action == UserSetAction::kick_user) {
            authorized = effective_value >= 3 || actor_has_policy("can_kick");
        }
        if (parsed->action == UserSetAction::create_user ||
            parsed->action == UserSetAction::create_user_without_password) {
            const auto target_value =
                static_cast<std::int16_t>(parsed->user_class);
            authorized = effective_value >= hub_settings.minimum_register &&
                effective_value - target_value >=
                    hub_settings.register_class_difference;
            if (!authorized && actor_has_policy("can_register") &&
                target_value <= 1) authorized = true;
        }

        if (!authorized && !database_.has_any_enabled_users()) {
            authorized =
                parsed->action == UserSetAction::create_user &&
                parsed->user_class == UserClass::master;
        }

        if (!authorized) {
            const std::string permission = authorization.permission.has_value()
                ? std::string(permission_name(*authorization.permission))
                : "unmapped";
            const std::string minimum = authorization.minimum_class.has_value()
                ? std::to_string(static_cast<std::int16_t>(
                    *authorization.minimum_class))
                : "none";
            send_all(sender_fd,
                     "IMSG " +
                         AdcProtocol::escape_adc(
                             "[authorization] rejected: permission=" +
                             permission + " minimum_class=" + minimum) +
                         "\n");
            return true;
        }

        if (parsed->action == UserSetAction::create_ban &&
            (parsed->duration_seconds == 0U ||
             parsed->moderation_target.kind !=
                 ModerationTargetKind::nickname) &&
            (!effective_class.has_value() ||
             *effective_class != UserClass::master)) {
            send_all(sender_fd,
                     "IMSG " + AdcProtocol::escape_adc(
                         "[set] rejected: Master(10) required for permanent or non-nickname bans") +
                     "\n");
            return true;
        }

        if ((parsed->action == UserSetAction::create_user ||
             parsed->action == UserSetAction::create_user_without_password)) {
            std::string nickname_error;
            if (!nickname_allowed(
                    parsed->username, hub_settings, nickname_error)) {
                send_all(sender_fd,
                         "IMSG " + AdcProtocol::escape_adc(
                             "[set] rejected: " + nickname_error) + "\n");
                return true;
            }
        }
        parsed->actor_username = *nick;

        const auto result = UserCommandProcessor::requires_live_sessions(
                                parsed->action)
            ? execute_live_user_command(sender_fd, *parsed)
            : user_commands_.execute(*parsed);
        if (result.success && !parsed->username.empty()) {
            refresh_client_policy(parsed->username);
        }
        if (result.success && parsed->action == UserSetAction::remove_user) {
            std::lock_guard lock(temporary_classes_mutex_);
            temporary_classes_.erase(parsed->username);
        }
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

UserSetResult Server::execute_live_user_command(
    int sender_fd,
    const UserSetCommand& command) {
    if (command.action == UserSetAction::disconnect_user) {
        int target_fd = -1;
        {
            std::lock_guard lock(clients_mutex_);
            for (const auto& [fd, client] : clients_) {
                if (!client.normal) continue;
                const auto target_nick = client_username(client);
                if (target_nick.has_value() &&
                    *target_nick == command.username) {
                    target_fd = fd;
                    break;
                }
            }
        }
        if (target_fd < 0) return {false, "user is not online"};
        send_all(
            target_fd,
            "IMSG Your\\ssession\\swas\\sdisconnected\\sby\\san\\sadministrator\n");
        ::shutdown(target_fd, SHUT_RDWR);
        return {true, "user disconnected without kick: username=" +
            command.username};
    }

    if (command.action == UserSetAction::kick_user) {
        std::unique_lock moderation_lock(moderation_mutex_);
        int target_fd = -1;
        std::string target_sid;
        std::string target_cid;
        std::string target_username;
        std::string actor_username;
        UserClass actor_class = UserClass::regular;
        UserClass target_class = UserClass::regular;
        RuntimeUserPolicy target_policy;
        const ModerationTarget nickname_target{
            ModerationTargetKind::nickname, command.username, {}};
        {
            std::lock_guard lock(clients_mutex_);
            const auto actor = clients_.find(sender_fd);
            if (actor == clients_.end()) return {false, "sender session not found"};
            const auto actor_nick = client_username(actor->second);
            if (actor_nick.has_value()) actor_username = *actor_nick;
            actor_class = actor->second.policy.user_class;

            for (const auto& [fd, client] : clients_) {
                if (!client.normal) continue;
                const auto target_nick = client_username(client);
                if (!target_nick.has_value() ||
                    !moderation_target_matches(
                        nickname_target, *target_nick, {}, {}, std::nullopt)) {
                    continue;
                }
                target_fd = fd;
                target_sid = client.sid;
                target_username = *target_nick;
                target_policy = client.policy;
                target_class = client.policy.user_class;
                const auto cid_field = client.inf_fields.find("ID");
                if (cid_field != client.inf_fields.end()) {
                    target_cid = cid_field->second;
                }
                break;
            }
        }
        if (target_fd < 0) return {false, "user is not online"};
        if (target_fd == sender_fd) return {false, "cannot kick your own session"};
        if (target_cid.empty()) return {false, "target ADC identity is unavailable"};

        {
            std::lock_guard lock(temporary_classes_mutex_);
            const auto actor_temporary = temporary_classes_.find(actor_username);
            if (actor_temporary != temporary_classes_.end()) {
                actor_class = actor_temporary->second;
            }
            const auto target_temporary = temporary_classes_.find(target_username);
            if (target_temporary != temporary_classes_.end()) {
                target_class = target_temporary->second;
            }
        }
        if (static_cast<std::int16_t>(actor_class) <=
            target_policy.kick_protect_class) {
            return {false, "target is protected from this actor class"};
        }
        const auto settings = database_.hub_settings();
        if (static_cast<std::int16_t>(actor_class) -
                static_cast<std::int16_t>(target_class) <
            settings.kick_class_difference) {
            return {false, "target class is outside the configured kick difference"};
        }
        const auto duration = command.duration_seconds == 0U
            ? static_cast<std::uint64_t>(settings.kick_rejoin_delay_seconds)
            : command.duration_seconds;
        if (duration > settings.maximum_temporary_ban_seconds) {
            return {false, "kick duration exceeds key.bans"};
        }
        const std::string reason = command.moderation_reason.empty()
            ? "Kick issued without an explicit reason"
            : command.moderation_reason;
        const ModerationTarget identity_target{
            ModerationTargetKind::identity, target_username, target_cid};
        const auto entry_id = database_.add_moderation_entry(
            ModerationAction::kick,
            identity_target,
            reason,
            actor_username.empty() ? std::string_view("operator")
                                   : std::string_view(actor_username),
            duration);
        moderation_lock.unlock();

        int target_socket = -1;
        {
            std::lock_guard lock(clients_mutex_);
            const auto target = clients_.find(target_fd);
            if (target == clients_.end() || target->second.sid != target_sid) {
                return {true, "kick recorded after target disconnected: id=" +
                    std::to_string(entry_id)};
            }
            target_socket = ::dup(target_fd);
            if (target_socket < 0) ::shutdown(target_fd, SHUT_RDWR);
        }
        if (target_socket >= 0) {
            send_all(target_socket,
                     "IMSG " + AdcProtocol::escape_adc(
                         "You were kicked: " + reason) + "\n");
            ::shutdown(target_socket, SHUT_RDWR);
            ::close(target_socket);
        }

        const std::string event = "[kick] " + target_username +
            " was kicked by " +
            (actor_username.empty() ? std::string("operator")
                                    : actor_username) +
            ": " + reason;
        std::vector<int> event_sockets;
        {
            std::lock_guard lock(clients_mutex_);
            event_sockets.reserve(clients_.size());
            for (const auto& [fd, client] : clients_) {
                if (!client.normal || fd == target_fd || client.policy.hide_kick ||
                    static_cast<std::int16_t>(actor_class) <=
                        client.policy.hide_kick_through_class) continue;
                const int socket = ::dup(fd);
                if (socket >= 0) event_sockets.push_back(socket);
            }
        }
        const auto event_message =
            "IMSG " + AdcProtocol::escape_adc(event) + "\n";
        for (const int socket : event_sockets) {
            send_all(socket, event_message);
            ::close(socket);
        }
        return {true, "user kicked: username=" + target_username +
            " entry_id=" + std::to_string(entry_id) +
            " duration_seconds=" + std::to_string(duration)};
    }

    if (command.action == UserSetAction::create_ban) {
        std::unique_lock moderation_lock(moderation_mutex_);
        struct MatchedSession {
            int fd{-1};
            std::string sid;
            std::string username;
            RuntimeUserPolicy policy;
            UserClass effective_class{UserClass::regular};
        };

        std::string actor_username;
        std::string actor_cid;
        std::string actor_address;
        std::optional<std::uint64_t> actor_share;
        UserClass actor_class = UserClass::regular;
        std::vector<MatchedSession> matched;
        {
            std::lock_guard lock(clients_mutex_);
            const auto actor = clients_.find(sender_fd);
            if (actor == clients_.end() || !actor->second.normal) {
                return {false, "sender session not found"};
            }
            const auto actor_nick = client_username(actor->second);
            if (actor_nick.has_value()) actor_username = *actor_nick;
            actor_class = actor->second.policy.user_class;
            actor_address = actor->second.remote_address;
            const auto actor_cid_field = actor->second.inf_fields.find("ID");
            if (actor_cid_field != actor->second.inf_fields.end()) {
                actor_cid = actor_cid_field->second;
            }
            const auto actor_share_field = actor->second.inf_fields.find("SS");
            if (actor_share_field != actor->second.inf_fields.end()) {
                std::uint64_t parsed_share = 0;
                const auto parsed = std::from_chars(
                    actor_share_field->second.data(),
                    actor_share_field->second.data() +
                        actor_share_field->second.size(),
                    parsed_share);
                if (parsed.ec == std::errc{} &&
                    parsed.ptr == actor_share_field->second.data() +
                        actor_share_field->second.size()) {
                    actor_share = parsed_share;
                }
            }
            if (moderation_target_matches(
                    command.moderation_target,
                    actor_username,
                    actor_cid,
                    actor_address,
                    actor_share)) {
                return {false, "ban target includes the acting session"};
            }

            for (const auto& [fd, client] : clients_) {
                if (!client.normal) continue;
                const auto nick = client_username(client);
                const auto cid_field = client.inf_fields.find("ID");
                const auto share_field = client.inf_fields.find("SS");
                std::optional<std::uint64_t> share;
                if (share_field != client.inf_fields.end()) {
                    std::uint64_t parsed_share = 0;
                    const auto parsed = std::from_chars(
                        share_field->second.data(),
                        share_field->second.data() + share_field->second.size(),
                        parsed_share);
                    if (parsed.ec == std::errc{} &&
                        parsed.ptr == share_field->second.data() +
                            share_field->second.size()) share = parsed_share;
                }
                if (moderation_target_matches(
                        command.moderation_target,
                        nick.has_value() ? std::string_view(*nick)
                                         : std::string_view{},
                        cid_field == client.inf_fields.end()
                            ? std::string_view{}
                            : std::string_view(cid_field->second),
                        client.remote_address,
                        share)) {
                    matched.push_back({
                        fd,
                        client.sid,
                        nick.has_value() ? *nick : std::string{},
                        client.policy,
                        client.policy.user_class});
                }
            }
        }

        {
            std::lock_guard lock(temporary_classes_mutex_);
            const auto actor_temporary = temporary_classes_.find(actor_username);
            if (actor_temporary != temporary_classes_.end()) {
                actor_class = actor_temporary->second;
            }
            for (auto& target : matched) {
                const auto temporary = temporary_classes_.find(target.username);
                if (temporary != temporary_classes_.end()) {
                    target.effective_class = temporary->second;
                }
            }
        }
        const auto settings = database_.hub_settings();
        if (command.duration_seconds >
            settings.maximum_temporary_ban_seconds) {
            return {false, "ban duration exceeds key.bans"};
        }
        for (const auto& target : matched) {
            if (static_cast<std::int16_t>(actor_class) <=
                    target.policy.kick_protect_class ||
                static_cast<std::int16_t>(actor_class) -
                        static_cast<std::int16_t>(target.effective_class) <
                    settings.kick_class_difference) {
                return {false, "a matched session is protected from this actor"};
            }
        }
        if (command.moderation_target.kind ==
            ModerationTargetKind::nickname) {
            const auto policy = database_.runtime_policy(
                command.moderation_target.value);
            auto effective_target_class = policy.user_class;
            {
                std::lock_guard lock(temporary_classes_mutex_);
                const auto temporary = temporary_classes_.find(
                    command.moderation_target.value);
                if (temporary != temporary_classes_.end()) {
                    effective_target_class = temporary->second;
                }
            }
            if (policy.registered &&
                (static_cast<std::int16_t>(actor_class) <=
                     policy.kick_protect_class ||
                 static_cast<std::int16_t>(actor_class) -
                         static_cast<std::int16_t>(effective_target_class) <
                     settings.kick_class_difference)) {
                return {false, "registered target is protected from this actor"};
            }
        }

        const auto entry_id = database_.add_moderation_entry(
            ModerationAction::ban,
            command.moderation_target,
            command.moderation_reason,
            actor_username,
            command.duration_seconds);
        moderation_lock.unlock();

        std::size_t disconnected = 0;
        std::vector<int> target_sockets;
        target_sockets.reserve(matched.size());
        for (const auto& candidate : matched) {
            std::lock_guard lock(clients_mutex_);
            const auto target = clients_.find(candidate.fd);
            if (target == clients_.end() ||
                target->second.sid != candidate.sid) continue;
            const int socket = ::dup(candidate.fd);
            if (socket >= 0) target_sockets.push_back(socket);
            else ::shutdown(candidate.fd, SHUT_RDWR);
            ++disconnected;
        }
        const auto ban_message =
            "IMSG " + AdcProtocol::escape_adc(
                "You were banned: " + command.moderation_reason) + "\n";
        for (const int socket : target_sockets) {
            send_all(socket, ban_message);
            ::shutdown(socket, SHUT_RDWR);
            ::close(socket);
        }
        return {true, "ban created: id=" + std::to_string(entry_id) +
            " disconnected=" + std::to_string(disconnected)};
    }

    if (command.action == UserSetAction::change_class_temporarily) {
        const auto details = database_.user_details(command.username);
        if (!details.has_value()) {
            return {false, "registered username not found"};
        }
        if (!details->enabled) {
            return {false, "registered username is disabled"};
        }
        {
            std::lock_guard lock(temporary_classes_mutex_);
            temporary_classes_[command.username] = command.user_class;
        }
        return {true, "temporary class changed until hub restart: username=" +
            command.username + " class=" +
            std::to_string(static_cast<std::int16_t>(command.user_class))};
    }

    struct OnlineUser {
        std::string username;
        std::string address;
    };
    std::vector<OnlineUser> users;
    {
        std::lock_guard lock(clients_mutex_);
        for (const auto& [fd, client] : clients_) {
            static_cast<void>(fd);
            if (!client.normal) continue;
            const auto nick_field = client.inf_fields.find("NI");
            if (nick_field == client.inf_fields.end()) continue;
            const auto decoded = decode_adc_value(nick_field->second);
            if (!decoded.has_value() || decoded->empty()) continue;
            users.push_back({*decoded, client.remote_address});
        }
    }

    if (command.action == UserSetAction::show_ip_and_hostname ||
        command.action == UserSetAction::show_hostname) {
        const auto found = std::find_if(
            users.begin(), users.end(), [&](const OnlineUser& user) {
                return user.username == command.username;
            });
        if (found == users.end()) return {false, "user is not online"};
        const auto hostname = hostname_for_address(found->address);
        if (command.action == UserSetAction::show_hostname) {
            return {true, "username=" + found->username +
                " hostname=" + hostname};
        }
        return {true, "username=" + found->username +
            " ip=" + found->address + " hostname=" + hostname};
    }

    std::vector<OnlineUser> matches;
    if (command.action == UserSetAction::find_users_by_ip) {
        if (!ipv4_host_order(command.query).has_value()) {
            return {false, "invalid IPv4 address"};
        }
        std::copy_if(users.begin(), users.end(), std::back_inserter(matches),
                     [&](const OnlineUser& user) {
                         return user.address == command.query;
                     });
    } else if (command.action == UserSetAction::find_users_by_ip_range) {
        const auto separator = command.query.find('-');
        if (separator == std::string::npos) {
            return {false, "expected IPv4 range start-end"};
        }
        const auto first = ipv4_host_order(
            std::string_view(command.query).substr(0, separator));
        const auto last = ipv4_host_order(
            std::string_view(command.query).substr(separator + 1U));
        if (!first.has_value() || !last.has_value() || *first > *last) {
            return {false, "invalid IPv4 range"};
        }
        std::copy_if(users.begin(), users.end(), std::back_inserter(matches),
                     [&](const OnlineUser& user) {
                         const auto address = ipv4_host_order(user.address);
                         return address.has_value() && *address >= *first &&
                                *address <= *last;
                     });
    } else if (command.action == UserSetAction::find_users_by_subnet) {
        const auto separator = command.query.find('/');
        if (separator == std::string::npos) {
            return {false, "expected IPv4 subnet address/prefix"};
        }
        const auto network = ipv4_host_order(
            std::string_view(command.query).substr(0, separator));
        unsigned int prefix = 0;
        const auto prefix_text =
            std::string_view(command.query).substr(separator + 1U);
        const auto parsed = std::from_chars(
            prefix_text.data(), prefix_text.data() + prefix_text.size(), prefix);
        if (!network.has_value() || parsed.ec != std::errc{} ||
            parsed.ptr != prefix_text.data() + prefix_text.size() || prefix > 32U) {
            return {false, "invalid IPv4 subnet"};
        }
        const std::uint32_t mask = prefix == 0U
            ? 0U
            : 0xFFFFFFFFU << (32U - prefix);
        std::copy_if(users.begin(), users.end(), std::back_inserter(matches),
                     [&](const OnlineUser& user) {
                         const auto address = ipv4_host_order(user.address);
                         return address.has_value() &&
                                ((*address & mask) == (*network & mask));
                     });
    } else {
        return {false, "unsupported live-session query"};
    }

    std::string response = "online users";
    if (matches.empty()) return {true, response + ": empty"};
    response += ": ";
    bool first = true;
    for (const auto& user : matches) {
        if (!first) response += "; ";
        first = false;
        response += user.username + "@" + user.address;
    }
    return {true, std::move(response)};
}

std::optional<UserClass> Server::temporary_class_for(
    std::string_view username) const {
    std::lock_guard lock(temporary_classes_mutex_);
    const auto found = temporary_classes_.find(std::string(username));
    if (found == temporary_classes_.end()) return std::nullopt;
    return found->second;
}

std::string Server::hostname_for_address(
    std::string_view address,
    bool moderation_lookup) const {
    if (!config_.dns_lookup && !moderation_lookup) {
        return "dns_lookup_disabled";
    }

    sockaddr_in socket_address{};
    socket_address.sin_family = AF_INET;
    const std::string address_text(address);
    if (::inet_pton(AF_INET, address_text.c_str(), &socket_address.sin_addr) != 1) {
        return moderation_lookup ? std::string{} : "unavailable";
    }

    std::array<char, NI_MAXHOST> host{};
    if (::getnameinfo(reinterpret_cast<const sockaddr*>(&socket_address),
                      sizeof(socket_address),
                      host.data(),
                      static_cast<socklen_t>(host.size()),
                      nullptr,
                      0,
                      NI_NAMEREQD) != 0) {
        return moderation_lookup ? std::string{} : "not_found";
    }
    return host.data();
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
    std::vector<int> sockets;
    {
        std::lock_guard lock(clients_mutex_);
        sockets.reserve(clients_.size());
        for (const auto& [fd, client] : clients_) {
            if (!client.normal) continue;
            const int socket = ::dup(fd);
            if (socket >= 0) sockets.push_back(socket);
        }
    }
    for (const int socket : sockets) {
        send_all(socket, message);
        ::close(socket);
    }
}

void Server::broadcast_from(int sender_fd, const std::string& message) {
    std::vector<int> sockets;
    {
        std::lock_guard lock(clients_mutex_);
        const auto sender = clients_.find(sender_fd);
        if (sender == clients_.end()) return;
        sockets.reserve(clients_.size());
        for (const auto& [fd, client] : clients_) {
            if (!client.normal) continue;
            if (fd != sender_fd &&
                static_cast<std::int16_t>(client.policy.user_class) <
                    sender->second.policy.hide_from_class) {
                continue;
            }
            const int socket = ::dup(fd);
            if (socket >= 0) sockets.push_back(socket);
        }
    }
    for (const int socket : sockets) {
        send_all(socket, message);
        ::close(socket);
    }
}

void Server::broadcast_current_inf(int sender_fd, bool remove_hidden) {
    std::vector<std::pair<int, std::string>> sends;
    {
        std::lock_guard lock(clients_mutex_);
        const auto sender = clients_.find(sender_fd);
        if (sender == clients_.end() || !sender->second.normal) return;
        sends.reserve(clients_.size());
        for (const auto& [fd, client] : clients_) {
            if (!client.normal) continue;
            auto message = build_current_inf_locked(
                sender->second, client.policy.user_class, fd == sender_fd);
            if (message.empty() && remove_hidden && fd != sender_fd) {
                message = "IQUI " + sender->second.sid + "\n";
            }
            if (message.empty()) continue;
            const int socket = ::dup(fd);
            if (socket >= 0) sends.emplace_back(socket, std::move(message));
        }
    }
    for (const auto& [socket, message] : sends) {
        send_all(socket, message);
        ::close(socket);
    }
}

void Server::route_direct(int sender_fd,
                          std::string_view target_sid,
                          const std::string& message,
                          bool echo_sender) {
    int target_fd = -1;
    int target_socket = -1;
    int sender_socket = -1;
    {
        std::lock_guard lock(clients_mutex_);
        const auto sender = clients_.find(sender_fd);
        if (sender == clients_.end()) return;
        for (const auto& [fd, client] : clients_) {
            if (client.normal && client.sid == target_sid) {
                if (fd != sender_fd &&
                    static_cast<std::int16_t>(client.policy.user_class) <
                        sender->second.policy.hide_from_class) {
                    break;
                }
                target_fd = fd;
                target_socket = ::dup(fd);
                break;
            }
        }
        if (echo_sender && sender_fd != target_fd && sender->second.normal) {
            sender_socket = ::dup(sender_fd);
        }
    }
    if (target_socket >= 0) {
        send_all(target_socket, message);
        ::close(target_socket);
    }
    if (sender_socket >= 0) {
        send_all(sender_socket, message);
        ::close(sender_socket);
    }
}

void Server::route_feature(int sender_fd, const AdcAction& action) {
    std::vector<int> sockets;
    {
        std::lock_guard lock(clients_mutex_);
        const auto sender = clients_.find(sender_fd);
        if (sender == clients_.end()) return;
        sockets.reserve(clients_.size());
        for (const auto& [fd, client] : clients_) {
            if (!client.normal) continue;
            if (fd != sender_fd &&
                static_cast<std::int16_t>(client.policy.user_class) <
                    sender->second.policy.hide_from_class) {
                continue;
            }
            if (!feature_match(client,
                               action.required_features,
                               action.excluded_features)) {
                continue;
            }
            const int socket = ::dup(fd);
            if (socket >= 0) sockets.push_back(socket);
        }
    }
    for (const int socket : sockets) {
        send_all(socket, action.routed_message);
        ::close(socket);
    }
}

void Server::disconnect_all() {
    std::vector<std::shared_ptr<SocketTransport>> transports;
    {
        std::lock_guard lock(transports_mutex_);
        for (const auto& [fd, transport] : transports_) {
            static_cast<void>(fd);
            transports.push_back(transport);
        }
    }
    for (const auto& transport : transports) {
        transport->shutdown();
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
    const ClientInfo& client,
    UserClass recipient_class,
    bool recipient_is_self) const {
    if (!recipient_is_self &&
        static_cast<std::int16_t>(recipient_class) <
            client.policy.hide_from_class) {
        return {};
    }

    const bool hide_share = client.policy.hide_share ||
        has_active_policy(client, "hide_share");
    std::string output = "BINF " + client.sid;
    for (const auto& [name, value] : client.inf_fields) {
        if (name == "PD") continue;
        if (hide_share && (name == "SS" || name == "SF" || name == "SL")) {
            continue;
        }
        output.push_back(' ');
        output += name;
        if (client.policy.hide_operator_key && name == "CT") {
            unsigned int client_type = 0;
            const auto parsed = std::from_chars(
                value.data(), value.data() + value.size(), client_type);
            if (parsed.ec == std::errc{} &&
                parsed.ptr == value.data() + value.size()) {
                client_type &= ~28U;
                output += std::to_string(client_type);
                continue;
            }
        }
        output += value;
    }
    output.push_back('\n');
    return output;
}

bool Server::has_active_policy(const ClientInfo& client,
                               std::string_view policy_key) noexcept {
    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    for (const auto& policy : client.policy.timed_policies) {
        if (policy.policy_key == policy_key && policy.expires_at > now) {
            return true;
        }
    }
    return false;
}

std::optional<std::string> Server::client_username(
    const ClientInfo& client) {
    const auto nick = client.inf_fields.find("NI");
    if (nick == client.inf_fields.end()) return std::nullopt;
    return decode_adc_value(nick->second);
}

void Server::refresh_client_policy(std::string_view username) {
    RuntimeUserPolicy policy;
    HubSettings settings;
    try {
        policy = database_.runtime_policy(username);
        settings = database_.hub_settings();
    } catch (const std::exception& ex) {
        std::cerr << "database policy refresh error: " << ex.what() << '\n';
        return;
    }

    std::vector<int> changed_clients;
    {
        std::lock_guard lock(clients_mutex_);
        for (auto& [fd, client] : clients_) {
            const auto nick = client_username(client);
            if (nick.has_value() && *nick == username) {
                client.policy = policy;
                if (!client.policy.password_change_required) {
                    client.password_deadline = 0;
                } else if (client.password_deadline == 0) {
                    const auto password_timeout = std::min(
                        settings.password_initial_timeout,
                        config_.timeout.Password);
                    client.password_deadline =
                        static_cast<std::int64_t>(std::time(nullptr)) +
                        static_cast<std::int64_t>(password_timeout);
                }
                changed_clients.push_back(fd);
            }
        }
    }
    for (const int fd : changed_clients) {
        broadcast_current_inf(fd, true);
    }
}

void Server::expire_client_policies() {
    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    std::vector<int> share_visibility_changed;
    std::vector<int> password_deadlines_expired;
    {
        std::lock_guard lock(clients_mutex_);
        for (auto& [fd, client] : clients_) {
            auto& policies = client.policy.timed_policies;
            bool share_expired = false;
            for (auto iterator = policies.begin(); iterator != policies.end();) {
                if (iterator->expires_at > now) {
                    ++iterator;
                    continue;
                }
                if (iterator->policy_key == "hide_share") share_expired = true;
                iterator = policies.erase(iterator);
            }
            if (share_expired) share_visibility_changed.push_back(fd);
            if (client.password_deadline > 0 &&
                client.password_deadline <= now) {
                client.password_deadline = 0;
                password_deadlines_expired.push_back(fd);
            }
        }
    }
    for (const int fd : share_visibility_changed) {
        broadcast_current_inf(fd);
    }
    for (const int fd : password_deadlines_expired) {
        send_all(fd,
                 "IMSG Password\\ssetup\\stimeout;\\suse\\s+passwd\\sbefore\\sthe\\sdeadline\n");
        ::shutdown(fd, SHUT_RDWR);
    }
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
    std::shared_ptr<SocketTransport> transport;
    {
        std::lock_guard lock(transports_mutex_);
        const auto current = transports_.find(fd);
        if (current != transports_.end()) {
            transport = current->second;
        } else {
            struct stat requested{};
            if (::fstat(fd, &requested) != 0) return false;
            for (const auto& [registered_fd, candidate] : transports_) {
                struct stat registered{};
                if (::fstat(registered_fd, &registered) == 0 &&
                    requested.st_dev == registered.st_dev &&
                    requested.st_ino == registered.st_ino) {
                    transport = candidate;
                    break;
                }
            }
            if (!transport) return false;
        }
    }
    const bool written = transport->write_all(
        message, std::chrono::seconds(config_.timeout.General));
    if (!written) transport->shutdown();
    return written;
}

}  // namespace dc24h
