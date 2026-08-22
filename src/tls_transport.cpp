/*
    tls_transport.cpp

    v0.0.12:
        - implement OpenSSL server transport with a configurable TLS minimum
        - enforce handshake/write deadlines and bounded output
        - disable compression, renegotiation and TLS 1.3 early data

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

// ----------------------------------// DECLARATION //--

#include "tls_transport.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <algorithm>
#include <climits>
#include <fcntl.h>
#include <stdexcept>

namespace dc24h {
namespace {

std::string openssl_error(std::string_view operation) {
    const unsigned long code = ERR_get_error();
    if (code == 0UL) return std::string(operation) + " failed";
    char message[256]{};
    ERR_error_string_n(code, message, sizeof(message));
    return std::string(operation) + " failed: " + message;
}

int minimum_protocol(std::string_view version) {
    if (version == "TLS1.3") return TLS1_3_VERSION;
    if (version == "TLS1.2") return TLS1_2_VERSION;
    return 0;
}

}  // namespace

bool valid_tls_settings(const TlsSettings& settings,
                        std::string& error) noexcept {
    if (settings.tls_only_mode && !settings.enabled) {
        error = "tls_only_mode requires TLS to be enabled";
        return false;
    }
    if (!settings.enabled) return true;
    if (!USE_TLS_PROXY_ENABLED && !USE_FEARTLS_PROXY_ENABLED) {
        error = "TLS was disabled at compile time";
        return false;
    }
    if (settings.port == 0U || settings.certificate.empty() ||
        settings.private_key.empty()) {
        error = "TLS port, certificate and private key are required";
        return false;
    }
    if (minimum_protocol(settings.minimum_version) == 0) {
        error = "tls_min_version must be TLS1.2 or TLS1.3";
        return false;
    }
    if (settings.handshake_timeout_seconds == 0U ||
        settings.handshake_timeout_seconds > 120U) {
        error = "TLS handshake timeout must be 1..120 seconds";
        return false;
    }
    return true;
}

TlsServerContext::TlsServerContext(const TlsSettings& settings)
    : minimum_version_(settings.minimum_version) {
    std::string error;
    if (!valid_tls_settings(settings, error) || !settings.enabled) {
        throw std::invalid_argument(error.empty() ? "TLS is not enabled" : error);
    }
    context_ = SSL_CTX_new(TLS_server_method());
    if (context_ == nullptr) throw std::runtime_error(openssl_error("SSL_CTX_new"));

    SSL_CTX_set_options(context_,
                        SSL_OP_NO_COMPRESSION |
                        SSL_OP_NO_RENEGOTIATION |
                        SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_max_early_data(context_, 0U);
    if (SSL_CTX_set_min_proto_version(
            context_, minimum_protocol(settings.minimum_version)) != 1 ||
        SSL_CTX_set_cipher_list(
            context_, "ECDHE+AESGCM:ECDHE+CHACHA20") != 1 ||
        SSL_CTX_set_ciphersuites(
            context_,
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_AES_128_GCM_SHA256") != 1) {
        SSL_CTX_free(context_);
        context_ = nullptr;
        throw std::runtime_error(openssl_error("TLS policy configuration"));
    }
    if (SSL_CTX_use_certificate_chain_file(
            context_, settings.certificate.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(
            context_, settings.private_key.c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context_) != 1) {
        SSL_CTX_free(context_);
        context_ = nullptr;
        throw std::runtime_error(openssl_error("TLS certificate/private key"));
    }
}

TlsServerContext::~TlsServerContext() {
    if (context_ != nullptr) SSL_CTX_free(context_);
}

SSL_CTX* TlsServerContext::native_handle() const noexcept {
    return context_;
}

std::string TlsServerContext::minimum_version() const {
    return minimum_version_;
}

SocketTransport::SocketTransport(int fd, IoLimits limits)
    : fd_(fd), limits_(limits) {
    if (fd_ < 0 || !valid_io_limits(limits_)) {
        throw std::invalid_argument("invalid socket transport arguments");
    }
    const int flags = ::fcntl(fd_, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd_, F_SETFL, flags | O_NONBLOCK) != 0) {
        throw std::runtime_error("unable to make client socket non-blocking");
    }
}

SocketTransport::~SocketTransport() {
    shutdown();
}

bool SocketTransport::wait_for(
    short events,
    std::chrono::steady_clock::time_point deadline) const {
    while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        const int timeout = static_cast<int>(
            std::min<long long>(remaining.count(), INT_MAX));
        pollfd descriptor{fd_, events, 0};
        const int result = ::poll(&descriptor, 1, timeout);
        if (result > 0) {
            return (descriptor.revents & events) != 0 &&
                   (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0;
        }
        if (result < 0 && errno == EINTR) continue;
        return false;
    }
    return false;
}

bool SocketTransport::AcceptTls(const TlsServerContext& context,
                                std::chrono::seconds timeout) {
    std::lock_guard lock(io_mutex_);
    if (ssl_ != nullptr) return false;
    ssl_ = SSL_new(context.native_handle());
    if (ssl_ == nullptr || SSL_set_fd(ssl_, fd_) != 1) {
        return false;
    }
    SSL_set_accept_state(ssl_);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (true) {
        const int result = SSL_accept(ssl_);
        if (result == 1) return true;
        const int error = SSL_get_error(ssl_, result);
        if (error == SSL_ERROR_WANT_READ) {
            if (!wait_for(POLLIN, deadline)) return false;
            continue;
        }
        if (error == SSL_ERROR_WANT_WRITE) {
            if (!wait_for(POLLOUT, deadline)) return false;
            continue;
        }
        return false;
    }
}

long SocketTransport::read_some(char* buffer, std::size_t size) {
    std::lock_guard lock(io_mutex_);
    if (ssl_ == nullptr) {
        return static_cast<long>(::recv(fd_, buffer, size, MSG_DONTWAIT));
    }
    const int bounded_size = static_cast<int>(
        std::min<std::size_t>(size, static_cast<std::size_t>(INT_MAX)));
    const int result = SSL_read(ssl_, buffer, bounded_size);
    if (result > 0) return result;
    const int error = SSL_get_error(ssl_, result);
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        errno = EAGAIN;
        return -1L;
    }
    if (error == SSL_ERROR_ZERO_RETURN) return 0L;
    errno = EIO;
    return -1L;
}

bool SocketTransport::write_all(std::string_view message,
                                std::chrono::seconds timeout) {
    if (!output_within_limits(message.size(), limits_)) return false;
    std::lock_guard lock(io_mutex_);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::size_t offset = 0U;
    while (offset < message.size()) {
        int result = 0;
        if (ssl_ == nullptr) {
            result = static_cast<int>(::send(
                fd_, message.data() + offset, message.size() - offset,
                MSG_NOSIGNAL | MSG_DONTWAIT));
            if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (!wait_for(POLLOUT, deadline)) return false;
                continue;
            }
        } else {
            const auto remaining = message.size() - offset;
            const int bounded_size = static_cast<int>(
                std::min<std::size_t>(remaining,
                                      static_cast<std::size_t>(INT_MAX)));
            result = SSL_write(ssl_, message.data() + offset, bounded_size);
            if (result <= 0) {
                const int error = SSL_get_error(ssl_, result);
                if (error == SSL_ERROR_WANT_READ) {
                    if (!wait_for(POLLIN, deadline)) return false;
                    continue;
                }
                if (error == SSL_ERROR_WANT_WRITE) {
                    if (!wait_for(POLLOUT, deadline)) return false;
                    continue;
                }
            }
        }
        if (result <= 0) return false;
        offset += static_cast<std::size_t>(result);
    }
    return true;
}

void SocketTransport::shutdown() noexcept {
    std::lock_guard lock(io_mutex_);
    if (ssl_ != nullptr) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (fd_ >= 0) {
        ::shutdown(fd_, SHUT_RDWR);
        ::close(fd_);
        fd_ = -1;
    }
}

int SocketTransport::fd() const noexcept {
    return fd_;
}

bool SocketTransport::encrypted() const noexcept {
    return ssl_ != nullptr;
}

bool SocketTransport::has_pending_input() const noexcept {
    std::lock_guard lock(io_mutex_);
    return ssl_ != nullptr && SSL_pending(ssl_) > 0;
}

}  // namespace dc24h
