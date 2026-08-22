/*
    version.cpp

    - canonical runtime version metadata

        v0.0.11:
            - set program version and release name to dc24h.eu-v0.0.11
            - set provenance to gpt-5.6-sol / 2026-08-22

        v0.0.10:
            - set program version and release name to dc24h.eu-v0.0.10
            - retain gpt-5.6-sol / 2026-08-21 provenance

        v0.0.09:
            - set program version and release name to dc24h.eu-v0.0.09
            - retain gpt-5.6-sol / 2026-08-21 provenance

        v0.0.08:
            - set program version and release name to dc24h.eu-v0.0.08
            - retain gpt-5.6-sol / 2026-08-21 provenance

        v0.0.07:
            - set program version and release name to dc24h.eu-v0.0.07
            - retain gpt-5.6-sol / 2026-08-21 provenance

        v0.0.06:
            - set program version to 0.0.06
            - set release name to dc24h.eu-v0.0.06
            - set provenance to gpt-5.6-sol / 2026-08-21

        v0.0.05:
            - set program version to 0.0.05
            - set release name to dc24h.eu-v0.0.05
            - retain gpt-5.6-sol / 2026-08-20 release provenance

        v0.0.04:
            - set program version to 0.0.04
            - set release name to dc24h.eu-v0.0.04
            - set project author/date metadata to gpt-5.6-sol / 2026-08-20

        v0.0.03:
            - set program version to 0.0.03
            - set release name to dc24h.eu-v0.0.03
            - retain project author/date metadata requested for this release

        v0.0.02:
            - set program version to 0.0.02
            - set release name to dc24h.eu-v0.0.02

        v0.0.01:
            - implement canonical program, release and author metadata

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

// ----------------------------------// DECLARATION //--

#include "version.hpp"

namespace dc24h {

std::string_view program_name() noexcept {
    return "dc24h.eu";
}

std::string_view version() noexcept {
    return "0.0.11";
}

std::string_view release_name() noexcept {
    return "dc24h.eu-v0.0.11";
}

std::string_view project_author() noexcept {
    return "gpt-5.6-sol";
}

std::string_view project_date() noexcept {
    return "2026-08-22";
}

}  // namespace dc24h
