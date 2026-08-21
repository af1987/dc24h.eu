/*
    adc_tests.cpp

    v0.0.08:
        - verify canonical 0.0.08 release metadata
        - reject duplicate and post-login mutable identity fields
        - verify field-specific rejection details for share changes

    v0.0.07:
        - verify canonical 0.0.07 runtime release metadata

    v0.0.06:
        - verify canonical 0.0.06 runtime release metadata and provenance date

    v0.0.05:
        - verify canonical 0.0.05 runtime release metadata

    v0.0.02:
        - test ADC Base32 and TIGR PID/CID verification with a fixed vector
        - test ADC 1.0.4 SUP/SID/INF login state transitions
        - verify PD removal, I4 correction and direct-message routing
        - verify sender SID spoofing is rejected

    Author: gpt-5.6-sol
    Date: 2026-08-21
*/

#include "adc_tests.hpp"

#include "adc.hpp"
#include "hash.hpp"
#include "version.hpp"

#include <cassert>
#include <iostream>
#include <string>

namespace dc24h::tests {

void run_hash_tests() {
    constexpr std::string_view pid =
        "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFY";
    constexpr std::string_view cid =
        "W6AIUW3CLDF6OGHNVE4JPDDJ2P74IWRCF2O36TA";

    assert(verify_tiger_pid_cid(pid, cid));
    assert(tiger_cid_from_pid(pid) == cid);
    assert(!verify_tiger_pid_cid(pid,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
}

void run_protocol_tests() {
    AdcProtocol protocol("dc24h.eu", "Test hub");
    AdcSession session;

    const auto handshake =
        protocol.handle_line("HSUP ADBASE ADTIGR",
                             "AAAB",
                             "127.0.0.1",
                             session);
    assert(session.state == AdcState::identify);
    assert(handshake.direct_messages.size() == 3U);
    assert(handshake.direct_messages[0] == "ISUP ADTIGR ADBASE\n");
    assert(handshake.direct_messages[1] == "ISID AAAB\n");

    const auto identify =
        protocol.handle_line(
            "BINF AAAB "
            "IDW6AIUW3CLDF6OGHNVE4JPDDJ2P74IWRCF2O36TA "
            "PDAAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFY "
            "NItester SUBASE,TIGR I40.0.0.0",
            "AAAB",
            "127.0.0.1",
            session);
    assert(session.state == AdcState::normal);
    assert(identify.became_normal);
    assert(identify.inf_update);
    assert(identify.routed_message.find(" PD") == std::string::npos);
    assert(identify.routed_message.find("I4127.0.0.1") != std::string::npos);

    const auto direct =
        protocol.handle_line("DMSG AAAB CCCC hello",
                             "AAAB",
                             "127.0.0.1",
                             session);
    assert(direct.route_mode == RouteMode::direct);
    assert(direct.target_sid == "CCCC");

    const auto spoof =
        protocol.handle_line("BMSG CCCC spoofed",
                             "AAAB",
                             "127.0.0.1",
                             session);
    assert(spoof.disconnect);
    assert(!spoof.direct_messages.empty());

    const auto rename = protocol.handle_line(
        "BINF AAAB NIrenamed", "AAAB", "127.0.0.1", session);
    assert(!rename.inf_update);
    assert(!rename.direct_messages.empty());

    const auto share_change = protocol.handle_line(
        "BINF AAAB SS42", "AAAB", "127.0.0.1", session);
    assert(!share_change.inf_update);
    assert(!share_change.direct_messages.empty());
    assert(share_change.direct_messages.front().find("FBSS") !=
           std::string::npos);

    AdcSession duplicate_session;
    protocol.handle_line(
        "HSUP ADBASE ADTIGR", "AAAD", "127.0.0.1", duplicate_session);
    const auto duplicate_identity = protocol.handle_line(
        "BINF AAAD "
        "IDW6AIUW3CLDF6OGHNVE4JPDDJ2P74IWRCF2O36TA "
        "PDAAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFY "
        "NIone NItwo",
        "AAAD", "127.0.0.1", duplicate_session);
    assert(duplicate_identity.disconnect);

    AdcSession ncdc_session;
    const auto ncdc_handshake = protocol.handle_line(
        "HSUP ADBASE ADTIGR", "AAAC", "127.0.0.1", ncdc_session);
    assert(!ncdc_handshake.disconnect);
    const auto ncdc_identify = protocol.handle_line(
        "BINF AAAC "
        "IDW6AIUW3CLDF6OGHNVE4JPDDJ2P74IWRCF2O36TA "
        "PDAAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFY "
        "NIncdc I40.0.0.0",
        "AAAC", "127.0.0.1", ncdc_session);
    assert(ncdc_identify.became_normal);
    assert(!ncdc_identify.disconnect);
}

}  // namespace dc24h::tests

int main() {
    assert(dc24h::version() == "0.0.08");
    assert(dc24h::release_name() == "dc24h.eu-v0.0.08");
    assert(dc24h::project_author() == "gpt-5.6-sol");
    assert(dc24h::project_date() == "2026-08-21");
    dc24h::tests::run_hash_tests();
    dc24h::tests::run_protocol_tests();
    std::cout << "dc24h.eu v0.0.08 tests passed\n";
    return 0;
}
