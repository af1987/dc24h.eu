/*
    version.cpp

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
    Date: 2026-08-19
*/

#include "version.hpp"

namespace dc24h {

std::string_view program_name() noexcept {
    return "dc24h.eu";
}

std::string_view version() noexcept {
    return "0.0.03";
}

std::string_view release_name() noexcept {
    return "dc24h.eu-v0.0.03";
}

std::string_view project_author() noexcept {
    return "gpt-5.6-sol";
}

std::string_view project_date() noexcept {
    return "2026-08-19";
}

}  // namespace dc24h
