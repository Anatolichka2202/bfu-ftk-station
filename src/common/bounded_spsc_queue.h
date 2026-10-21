#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <optional>
#include <utility>
#include <type_traits>

namespace telemetry {

template <typename T, std::size_t Capacity>
class BoundedSpscQueue {
    static_assert(Capacity >= 2);

public:
    bool tryPush(T value) noexcept(std::is_nothrow_move_assignable_v<T>) {
        const auto head = head_.load(std::memory_order_relaxed);
        const auto next = increment(head);
        if (next == tail_.load(std::memory_order_acquire)) {
            return false;
        }
        buffer_[head] = std::move(value);
        head_.store(next, std::memory_order_release);
        return true;
    }

    bool tryPop(T& out) noexcept(std::is_nothrow_move_assignable_v<T>) {
        const auto tail = tail_.load(std::memory_order_relaxed);
        if (tail == head_.load(std::memory_order_acquire)) {
            return false;
        }
        out = std::move(*buffer_[tail]);
        buffer_[tail].reset();
        tail_.store(increment(tail), std::memory_order_release);
        return true;
    }

    [[nodiscard]] std::size_t approximateSize() const noexcept {
        const auto head = head_.load(std::memory_order_acquire);
        const auto tail = tail_.load(std::memory_order_acquire);
        return head >= tail ? head - tail : Capacity - tail + head;
    }

    [[nodiscard]] static constexpr std::size_t usableCapacity() noexcept {
        return Capacity - 1;
    }

private:
    static constexpr std::size_t increment(std::size_t value) noexcept {
        return (value + 1) % Capacity;
    }

    std::array<std::optional<T>, Capacity> buffer_{};
    alignas(64) std::atomic<std::size_t> head_{0};
    alignas(64) std::atomic<std::size_t> tail_{0};
};

} // namespace telemetry
