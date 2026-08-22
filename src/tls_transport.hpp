/*
    tls_transport.hpp

    v0.0.12:
        - declare USE_TLS_PROXY and USE_FEARTLS_PROXY transport capabilities
        - declare TLS 1.2/1.3 server context and bounded socket transport

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

// ----------------------------------// DECLARATION //--

#pragma once

#include "io_limits.hpp"

#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

namespace dc24h {

inline constexpr bool USE_TLS_PROXY_ENABLED =
#ifdef USE_TLS_PROXY
    true;
#else
    false;
#endif

inline constexpr bool USE_FEARTLS_PROXY_ENABLED =
#ifdef USE_FEARTLS_PROXY
    true;
#else
    false;
#endif

struct TlsSettings {
    bool enabled{false};
    bool tls_only_mode{false};
    unsigned short port{1512};
    std::string certificate;
    std::string private_key;
    std::string minimum_version{"TLS1.3"};
    unsigned int handshake_timeout_seconds{10};
};

class TlsServerContext {
public:
    explicit TlsServerContext(const TlsSettings& settings);
    ~TlsServerContext();

    TlsServerContext(const TlsServerContext&) = delete;
    TlsServerContext& operator=(const TlsServerContext&) = delete;

    SSL_CTX* native_handle() const noexcept;
    std::string minimum_version() const;

private:
    SSL_CTX* context_{nullptr};
    std::string minimum_version_;
};

class SocketTransport {
public:
    SocketTransport(int fd, IoLimits limits);
    ~SocketTransport();

    SocketTransport(const SocketTransport&) = delete;
    SocketTransport& operator=(const SocketTransport&) = delete;

    bool AcceptTls(const TlsServerContext& context,
                   std::chrono::seconds timeout);
    long read_some(char* buffer, std::size_t size);
    bool write_all(std::string_view message,
                   std::chrono::seconds timeout);
    void shutdown() noexcept;
    int fd() const noexcept;
    bool encrypted() const noexcept;
    bool has_pending_input() const noexcept;

private:
    bool wait_for(short events,
                  std::chrono::steady_clock::time_point deadline) const;

    int fd_{-1};
    SSL* ssl_{nullptr};
    IoLimits limits_;
    mutable std::mutex io_mutex_;
};

bool valid_tls_settings(const TlsSettings& settings,
                        std::string& error) noexcept;

}  // namespace dc24h
