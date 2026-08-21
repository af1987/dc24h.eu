/*
    server.hpp

    v0.0.06:
        - enforce expiring chat, PM, search and download restrictions
        - add protected kick and non-punitive disconnect actions
        - filter INF visibility, share and operator flags by account policy

    v0.0.05:
        - add private online-user IP, hostname, range and subnet queries
        - retain temporary class overrides in memory until restart
        - add loopback-only +passwd first-password self-service

    v0.0.03:
        - integrate protected !set user-management commands
        - retain peer address for command authorization
        - require Admin/Master plus loopback; allow first local Master bootstrap

    v0.0.02:
        - track per-client NORMAL state INF fields and advertised features
        - add ADC B/D/E/F routing helpers and target SID lookup
        - add login user-list synchronization before broadcasting new BINF

    v0.0.01:
        - add IPv4 TCP listener and per-client worker model
        - add ADC SID allocation and message broadcast support
        - add graceful shutdown contract for systemd SIGTERM

    Author: gpt-5.6-sol
    Date: 2026-08-21
*/

#pragma once

#include "adc.hpp"
#include "config.hpp"
#include "database.hpp"
#include "user_commands.hpp"

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
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
        std::string remote_address;
        bool normal{false};
        std::map<std::string, std::string> inf_fields;
        std::unordered_set<std::string> features;
        RuntimeUserPolicy policy;
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
    bool handle_user_set_command(int sender_fd, const AdcAction& action);
    bool handle_opchat_command(int sender_fd, const AdcAction& action);
    UserSetResult execute_live_user_command(int sender_fd,
                                            const UserSetCommand& command);
    bool enforce_sender_policy(int sender_fd, const AdcAction& action);
    void refresh_client_policy(std::string_view username);
    void expire_client_policies();
    std::optional<UserClass> temporary_class_for(
        std::string_view username) const;
    std::string hostname_for_address(std::string_view address) const;
    static std::optional<std::string> extract_bmsg_text(
        const std::string& message);
    static std::optional<std::string> decode_adc_value(
        std::string_view value);

    void broadcast(const std::string& message);
    void broadcast_from(int sender_fd, const std::string& message);
    void broadcast_current_inf(int sender_fd, bool remove_hidden = false);
    void route_direct(int sender_fd,
                      std::string_view target_sid,
                      const std::string& message,
                      bool echo_sender);
    void route_feature(int sender_fd, const AdcAction& action);
    void disconnect_all();
    void join_workers();

    std::string build_current_inf_locked(
        const ClientInfo& client,
        UserClass recipient_class,
        bool recipient_is_self = false) const;
    static bool has_active_policy(const ClientInfo& client,
                                  std::string_view policy_key) noexcept;
    static std::optional<std::string> client_username(
        const ClientInfo& client);
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
    UserCommandProcessor user_commands_;

    std::atomic<std::uint32_t> sid_counter_{1};
    std::mutex clients_mutex_;
    std::unordered_map<int, ClientInfo> clients_;

    mutable std::mutex temporary_classes_mutex_;
    std::unordered_map<std::string, UserClass> temporary_classes_;

    std::mutex workers_mutex_;
    std::vector<std::thread> workers_;

    int listen_fd_{-1};
};

}  // namespace dc24h
