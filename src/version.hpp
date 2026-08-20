/*
    version.hpp

    - canonical runtime version metadata API

        v0.0.04:
            - raise canonical release metadata to dc24h.eu-v0.0.04
            - retain author/date accessors for release provenance

        v0.0.03:
            - raise canonical release metadata to dc24h.eu-v0.0.03

        v0.0.02:
            - raise canonical release metadata to dc24h.eu-v0.0.02

        v0.0.01:
            - add canonical program, release and author metadata

    Author: gpt-5.6-sol
    Date: 2026-08-20
*/

// ----------------------------------// DECLARATION //--

#pragma once

#include <string_view>

namespace dc24h {

std::string_view program_name() noexcept;
std::string_view version() noexcept;
std::string_view release_name() noexcept;
std::string_view project_author() noexcept;
std::string_view project_date() noexcept;

}  // namespace dc24h
