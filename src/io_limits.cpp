/*
    io_limits.cpp

    v0.0.12:
        - enforce MAX_MESS_SIZE and mLineSizeMax before buffer growth
        - enforce MAX_SEND_SIZE and max_outbuf_size for every queued message

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

// ----------------------------------// DECLARATION //--

#include "io_limits.hpp"

#include <algorithm>
#include <stdexcept>

namespace dc24h {

BoundedLineReader::BoundedLineReader(std::size_t mLineSizeMax)
    : mLineSizeMax_(mLineSizeMax) {
    if (mLineSizeMax_ == 0U || mLineSizeMax_ > MAX_MESS_SIZE) {
        throw std::invalid_argument("mLineSizeMax must be 1..MAX_MESS_SIZE");
    }
    pending_.reserve(std::min<std::size_t>(mLineSizeMax_, 8192U));
}

ReadLineResult BoundedLineReader::ReadLineLocal(std::string_view input) {
    ReadLineResult result;
    std::size_t offset = 0U;
    while (offset < input.size()) {
        const auto newline = input.find('\n', offset);
        const auto end = newline == std::string_view::npos
            ? input.size()
            : newline;
        const auto fragment_size = end - offset;
        if (fragment_size > mLineSizeMax_ - pending_.size()) {
            pending_.clear();
            result.lines.clear();
            result.status = ReadLineStatus::overflow;
            return result;
        }
        pending_.append(input.substr(offset, fragment_size));
        if (newline == std::string_view::npos) {
            result.status = result.lines.empty()
                ? ReadLineStatus::incomplete
                : ReadLineStatus::complete;
            return result;
        }
        result.lines.push_back(std::move(pending_));
        pending_.clear();
        offset = newline + 1U;
    }
    result.status = result.lines.empty()
        ? ReadLineStatus::incomplete
        : ReadLineStatus::complete;
    return result;
}

std::size_t BoundedLineReader::buffered_size() const noexcept {
    return pending_.size();
}

bool valid_io_limits(const IoLimits& limits) noexcept {
    return limits.mLineSizeMax > 0U &&
           limits.mLineSizeMax <= MAX_MESS_SIZE &&
           limits.max_outbuf_size >= limits.mLineSizeMax + 1U &&
           limits.max_outbuf_size <= MAX_SEND_SIZE;
}

bool output_within_limits(std::size_t size,
                          const IoLimits& limits) noexcept {
    return size <= MAX_SEND_SIZE && size <= limits.max_outbuf_size;
}

}  // namespace dc24h
