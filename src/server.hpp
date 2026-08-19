/*
    server.hpp

    v0.0.01:
        - add IPv4 TCP listener and per-client worker model
        - add ADC SID allocation and message broadcast support
        - add graceful shutdown contract for systemd SIGTERM

    Author: gpt-5.6-sol
    Date: 2026-08-19
*/

#pragma once

#include "adc.hpp"
#include "config.hpp"
#include "database.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace dc24h {

class Server {
public:
    Server(const Config& config, const AdcProtocol& protocol, Database& database);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    int run(const std::atomic_bool& stop_requested);

private:
    int create_listener() const;
    void client_loop(int client_fd, std::string sid, std::string remote_address);
    void broadcast(int sender_fd, const std::string& message, BroadcastMode mode);
    void disconnect_all();
    void join_workers();
    std::string next_sid();
    static bool send_all(int fd, const std::string& message);

    const Config& config_;
    const AdcProtocol& protocol_;
    Database& database_;

    std::atomic<std::uint32_t> sid_counter_{1};
    std::mutex clients_mutex_;
    std::unordered_map<int, std::string> clients_;

    std::mutex workers_mutex_;
    std::vector<std::thread> workers_;

    int listen_fd_{-1};
};

}  // namespace dc24h
