/*
    io_limits.hpp

    v0.0.12:
        - declare hard input/output buffer ceilings
        - declare ReadLineLocal() with configurable mLineSizeMax

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

// ----------------------------------// DECLARATION //--

#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace dc24h {

inline constexpr std::size_t MAX_MESS_SIZE = 65535U;
inline constexpr std::size_t MAX_SEND_SIZE = 1048576U;

struct IoLimits {
    std::size_t mLineSizeMax{MAX_MESS_SIZE};
    std::size_t max_outbuf_size{262144U};
};

enum class ReadLineStatus {
    complete,
    incomplete,
    overflow
};

struct ReadLineResult {
    ReadLineStatus status{ReadLineStatus::incomplete};
    std::vector<std::string> lines;
};

class BoundedLineReader {
public:
    explicit BoundedLineReader(std::size_t mLineSizeMax);

    ReadLineResult ReadLineLocal(std::string_view input);
    std::size_t buffered_size() const noexcept;

private:
    std::size_t mLineSizeMax_;
    std::string pending_;
};

bool valid_io_limits(const IoLimits& limits) noexcept;
bool output_within_limits(std::size_t size,
                          const IoLimits& limits) noexcept;

}  // namespace dc24h
