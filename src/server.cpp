/*
    server.cpp

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

#include <array>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace dc24h {

Server::Server(const Config& config, const AdcProtocol& protocol, Database& database)
    : config_(config), protocol_(protocol), database_(database) {}

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
            throw std::runtime_error("poll failed: " + std::string(std::strerror(errno)));
        }
        if (poll_result == 0) continue;
        if ((descriptor.revents & POLLIN) == 0) continue;

        sockaddr_in peer{};
        socklen_t peer_length = sizeof(peer);
        const int client_fd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&peer), &peer_length);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            std::cerr << "accept failed: " << std::strerror(errno) << '\n';
            continue;
        }

        char address_buffer[INET_ADDRSTRLEN]{};
        const char* address = ::inet_ntop(AF_INET, &peer.sin_addr, address_buffer, sizeof(address_buffer));
        const std::string remote_address = address != nullptr ? address : "unknown";

        std::string sid;
        {
            std::lock_guard lock(clients_mutex_);
            if (clients_.size() >= config_.max_clients) {
                ::close(client_fd);
                continue;
            }
            sid = next_sid();
            clients_.emplace(client_fd, sid);
        }

        try {
            database_.record_event(sid, "connect", remote_address);
        } catch (const std::exception& ex) {
            std::cerr << "database event error: " << ex.what() << '\n';
        }

        std::lock_guard worker_lock(workers_mutex_);
        workers_.emplace_back(&Server::client_loop, this, client_fd, sid, remote_address);
    }

    disconnect_all();
    join_workers();
    return 0;
}

int Server::create_listener() const {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        throw std::runtime_error("socket failed: " + std::string(std::strerror(errno)));
    }

    int reuse = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
        ::close(fd);
        throw std::runtime_error("setsockopt(SO_REUSEADDR) failed");
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config_.listen_port);

    if (::inet_pton(AF_INET, config_.listen_address.c_str(), &address.sin_addr) != 1) {
        ::close(fd);
        throw std::runtime_error("listen_address must be a valid IPv4 address");
    }

    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
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

void Server::client_loop(int client_fd, std::string sid, std::string remote_address) {
    std::array<char, 8192> buffer{};
    std::string pending;
    pending.reserve(8192);

    bool finished = false;
    while (!finished) {
        const auto received = ::recv(client_fd, buffer.data(), buffer.size(), 0);
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
            pending.erase(0, newline + 1);
            if (!line.empty() && line.back() == '\r') line.pop_back();

            if (line.size() > 65535) {
                finished = true;
                break;
            }

            const auto action = protocol_.handle_line(line, sid);
            for (const auto& message : action.direct_messages) {
                if (!send_all(client_fd, message)) {
                    finished = true;
                    break;
                }
            }
            if (finished) break;

            if (action.broadcast_mode != BroadcastMode::none) {
                broadcast(client_fd, action.broadcast_message, action.broadcast_mode);
            }
            if (action.disconnect) {
                finished = true;
                break;
            }
        }

        if (pending.size() > 65535) {
            finished = true;
        }
    }

    {
        std::lock_guard lock(clients_mutex_);
        clients_.erase(client_fd);
    }

    ::shutdown(client_fd, SHUT_RDWR);
    ::close(client_fd);

    try {
        database_.record_event(sid, "disconnect", remote_address);
    } catch (const std::exception& ex) {
        std::cerr << "database event error: " << ex.what() << '\n';
    }

    broadcast(-1, "IQUI " + sid + "\n", BroadcastMode::all);
}

void Server::broadcast(int sender_fd, const std::string& message, BroadcastMode mode) {
    std::lock_guard lock(clients_mutex_);
    for (const auto& [fd, sid] : clients_) {
        static_cast<void>(sid);
        if (mode == BroadcastMode::others && fd == sender_fd) continue;
        if (mode == BroadcastMode::none) continue;
        send_all(fd, message);
    }
}

void Server::disconnect_all() {
    std::lock_guard lock(clients_mutex_);
    for (const auto& [fd, sid] : clients_) {
        static_cast<void>(sid);
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

std::string Server::next_sid() {
    constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const std::uint32_t value = sid_counter_.fetch_add(1) & 0x000FFFFFU;

    std::string sid(4, 'A');
    std::uint32_t remaining = value;
    for (int index = 3; index >= 0; --index) {
        sid[static_cast<std::size_t>(index)] = alphabet[remaining & 0x1FU];
        remaining >>= 5U;
    }
    return sid;
}

bool Server::send_all(int fd, const std::string& message) {
    std::size_t offset = 0;
    while (offset < message.size()) {
        const auto sent = ::send(fd,
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
