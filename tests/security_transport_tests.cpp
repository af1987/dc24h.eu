/*
    security_transport_tests.cpp

    v0.0.12:
        - verify ReadLineLocal hard limits across fragmented input
        - verify output ceilings and TLS/TLS-only configuration invariants

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

// ----------------------------------// DECLARATION //--

#include "security_transport_tests.hpp"

#include "io_limits.hpp"
#include "tls_transport.hpp"

#include <cassert>
#include <iostream>
#include <string>

namespace dc24h::tests {

void run_security_transport_tests() {
    BoundedLineReader reader(8U);
    auto partial = reader.ReadLineLocal("1234");
    assert(partial.status == ReadLineStatus::incomplete);
    assert(reader.buffered_size() == 4U);

    auto complete = reader.ReadLineLocal("5678\nA\n");
    assert(complete.status == ReadLineStatus::complete);
    assert(complete.lines.size() == 2U);
    assert(complete.lines[0] == "12345678");
    assert(complete.lines[1] == "A");
    assert(reader.buffered_size() == 0U);

    auto overflow = reader.ReadLineLocal("123456789");
    assert(overflow.status == ReadLineStatus::overflow);
    assert(overflow.lines.empty());
    assert(reader.buffered_size() == 0U);

    IoLimits limits;
    assert(valid_io_limits(limits));
    assert(output_within_limits(limits.max_outbuf_size, limits));
    assert(!output_within_limits(limits.max_outbuf_size + 1U, limits));
    limits.mLineSizeMax = MAX_MESS_SIZE + 1U;
    assert(!valid_io_limits(limits));

    TlsSettings tls;
    std::string error;
    assert(valid_tls_settings(tls, error));
    tls.tls_only_mode = true;
    assert(!valid_tls_settings(tls, error));
    tls.enabled = true;
    tls.port = 1512U;
    tls.certificate = "/tmp/server.crt";
    tls.private_key = "/tmp/server.key";
    tls.minimum_version = "TLS1.3";
    assert(valid_tls_settings(tls, error));
    tls.minimum_version = "TLS1.1";
    assert(!valid_tls_settings(tls, error));
    assert(USE_TLS_PROXY_ENABLED);
    assert(USE_FEARTLS_PROXY_ENABLED);
}

}  // namespace dc24h::tests

int main() {
    dc24h::tests::run_security_transport_tests();
    std::cout << "security transport tests passed\n";
    return 0;
}
