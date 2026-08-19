/*
    server.hpp

    v0.0.02:
        - track per-client NORMAL state INF fields and advertised features
        - add ADC B/D/E/F routing helpers and target SID lookup
        - add login user-list synchronization before broadcasting new BINF

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
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
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
    struct ClientInfo {
        std::string sid;
        bool normal{false};
        std::map<std::string, std::string> inf_fields;
        std::unordered_set<std::string> features;
    };

    int create_listener() const;
    void client_loop(int client_fd, std::string sid, std::string remote_address);

    bool finish_identification(
        int client_fd,
        const std::vector<std::pair<std::string, std::string>>& fields);
    void apply_inf_update(
        int client_fd,
        const std::vector<std::pair<std::string, std::string>>& fields);
    void route_action(int sender_fd, const AdcAction& action);
    void broadcast(const std::string& message);
    void route_direct(int sender_fd,
                      std::string_view target_sid,
                      const std::string& message,
                      bool echo_sender);
    void route_feature(const AdcAction& action);
    void disconnect_all();
    void join_workers();

    std::string build_current_inf_locked(const ClientInfo& client) const;
    static std::unordered_set<std::string> parse_feature_list(
        const std::string& value);
    static bool feature_match(
        const ClientInfo& client,
        const std::vector<std::string>& required,
        const std::vector<std::string>& excluded);

    std::string next_sid();
    static bool send_all(int fd, const std::string& message);

    const Config& config_;
    const AdcProtocol& protocol_;
    Database& database_;

    std::atomic<std::uint32_t> sid_counter_{1};
    std::mutex clients_mutex_;
    std::unordered_map<int, ClientInfo> clients_;

    std::mutex workers_mutex_;
    std::vector<std::thread> workers_;

    int listen_fd_{-1};
};

}  // namespace dc24h
