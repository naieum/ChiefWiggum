"""
Rate Limiter for Guardian-Agent

Ensures testing doesn't overwhelm target systems or trigger
rate limiting defenses.

Thread-safe implementation with proper token bucket algorithm.
"""

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    requests_per_second: float = 10.0
    burst_limit: int = 20
    backoff_factor: float = 2.0
    max_backoff_seconds: float = 60.0
    retry_on_429: bool = True
    max_retries: int = 3


class RateLimiter:
    """
    Thread-safe token bucket rate limiter with adaptive backoff.

    Prevents overwhelming target systems during testing by:
    - Using proper token bucket with burst support
    - Thread-safe operations with lock protection
    - Exponential backoff on rate limit responses
    - Adaptive rate reduction based on server behavior
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()

        # Thread safety lock - protects ALL shared state
        self._lock = threading.RLock()

        # Token bucket state
        self._tokens = float(self.config.burst_limit)
        self._last_refill = time.time()

        # Request tracking for stats
        self._request_times: deque = deque(maxlen=1000)

        # Backoff state
        self._current_backoff: float = 0.0
        self._last_backoff_time: Optional[float] = None
        self._consecutive_429s: int = 0
        self._last_429_time: Optional[float] = None

    def _refill_tokens(self, now: Optional[float] = None) -> None:
        """
        Refill tokens based on elapsed time.

        MUST be called while holding the lock.
        """
        if now is None:
            now = time.time()

        elapsed = now - self._last_refill
        tokens_to_add = elapsed * self.config.requests_per_second

        self._tokens = min(
            float(self.config.burst_limit),
            self._tokens + tokens_to_add
        )
        self._last_refill = now

    def wait_if_needed(self) -> float:
        """
        Wait if necessary to maintain rate limit.

        Thread-safe implementation using token bucket with locks.

        Returns:
            float: Actual wait time in seconds
        """
        with self._lock:
            now = time.time()

            # First, handle any pending backoff from 429s
            if self._current_backoff > 0 and self._last_backoff_time is not None:
                backoff_elapsed = now - self._last_backoff_time
                if backoff_elapsed < self._current_backoff:
                    remaining_backoff = self._current_backoff - backoff_elapsed
                    # Release lock during sleep to allow other operations
                    self._lock.release()
                    try:
                        time.sleep(remaining_backoff)
                    finally:
                        self._lock.acquire()
                    # Clear backoff after waiting
                    self._current_backoff = 0
                    self._last_backoff_time = None
                    return remaining_backoff
                else:
                    # Backoff period has passed
                    self._current_backoff = 0
                    self._last_backoff_time = None

            # Refill token bucket
            self._refill_tokens(now)

            # Check if we have tokens available
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return 0.0

            # Calculate wait time until next token is available
            tokens_deficit = 1.0 - self._tokens
            wait_time = tokens_deficit / self.config.requests_per_second

            if wait_time > 0:
                # Release lock during sleep
                self._lock.release()
                try:
                    time.sleep(wait_time)
                finally:
                    self._lock.acquire()

                # After sleep, refill and consume token
                self._refill_tokens()
                self._tokens = max(0.0, self._tokens - 1.0)
                return wait_time

            return 0.0

    def record_request(self) -> None:
        """Record that a request was made - thread-safe"""
        with self._lock:
            self._request_times.append(time.time())

    def record_rate_limited(self) -> None:
        """
        Record that we received a 429 response - thread-safe.

        Applies exponential backoff to all subsequent requests.
        """
        with self._lock:
            now = time.time()
            self._consecutive_429s += 1
            self._last_429_time = now

            # Calculate exponential backoff
            backoff = min(
                self.config.backoff_factor ** self._consecutive_429s,
                self.config.max_backoff_seconds
            )
            self._current_backoff = backoff
            self._last_backoff_time = now

            # Reduce token count to discourage further requests
            self._tokens = max(0.0, self._tokens - 0.5)

    def record_success(self) -> None:
        """Record a successful request (no rate limit) - thread-safe"""
        with self._lock:
            self._consecutive_429s = 0
            # Gradually restore tokens on success (small bonus)
            self._tokens = min(
                float(self.config.burst_limit),
                self._tokens + 0.1
            )

    def can_retry(self) -> bool:
        """Check if we should retry after rate limiting - thread-safe"""
        with self._lock:
            if not self.config.retry_on_429:
                return False
            return self._consecutive_429s <= self.config.max_retries

    def get_stats(self) -> dict:
        """Get current rate limiter statistics - thread-safe"""
        with self._lock:
            now = time.time()
            window_start = now - 1.0

            # Create snapshot for safe iteration
            request_times_snapshot = list(self._request_times)

            requests_in_window = sum(
                1 for t in request_times_snapshot if t >= window_start
            )

            return {
                "requests_in_window": requests_in_window,
                "max_requests_per_second": self.config.requests_per_second,
                "current_backoff": self._current_backoff,
                "consecutive_429s": self._consecutive_429s,
                "available_tokens": self._tokens,
                "burst_limit": self.config.burst_limit,
                "can_continue": self.can_retry() or self._consecutive_429s == 0
            }

    def reset(self) -> None:
        """Reset rate limiter state - thread-safe"""
        with self._lock:
            self._tokens = float(self.config.burst_limit)
            self._last_refill = time.time()
            self._request_times.clear()
            self._current_backoff = 0.0
            self._last_backoff_time = None
            self._consecutive_429s = 0
            self._last_429_time = None


class AdaptiveRateLimiter(RateLimiter):
    """
    Thread-safe rate limiter that adapts based on target response.

    Automatically adjusts rate based on server response times
    and error rates with proper synchronization.
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        super().__init__(config)
        # Adaptive state (protected by parent lock)
        self._response_times: deque = deque(maxlen=100)
        self._error_count: int = 0
        self._success_count: int = 0
        self._min_requests_per_second: float = 1.0
        self._max_requests_per_second: float = 50.0

    def record_response_time(self, response_time_ms: float) -> None:
        """Record a response time for adaptive adjustment - thread-safe"""
        with self._lock:
            self._response_times.append(response_time_ms)

            # Only adjust if we have enough samples
            if len(self._response_times) >= 10:
                recent_times = list(self._response_times)[-10:]
                recent_avg = sum(recent_times) / 10
                overall_avg = sum(self._response_times) / len(self._response_times)

                # Server is slowing down, reduce rate
                if recent_avg > overall_avg * 1.5:
                    self.config.requests_per_second = max(
                        self._min_requests_per_second,
                        self.config.requests_per_second * 0.8
                    )

    def record_error(self) -> None:
        """Record an error response - thread-safe"""
        with self._lock:
            self._error_count += 1

            # If error rate is high, slow down
            total = self._error_count + self._success_count
            if total >= 10:
                error_rate = self._error_count / total
                if error_rate > 0.1:  # More than 10% errors
                    self.config.requests_per_second = max(
                        self._min_requests_per_second,
                        self.config.requests_per_second * 0.5
                    )

    def record_success(self) -> None:
        """Record a successful request - thread-safe"""
        with self._lock:
            # Reset consecutive 429s
            self._consecutive_429s = 0
            self._success_count += 1

            # Gradually restore tokens
            self._tokens = min(
                float(self.config.burst_limit),
                self._tokens + 0.1
            )

            # If things are going well, gradually increase rate
            total = self._error_count + self._success_count
            if total >= 20:
                error_rate = self._error_count / total
                if error_rate < 0.05:  # Less than 5% errors
                    self.config.requests_per_second = min(
                        self._max_requests_per_second,
                        self.config.requests_per_second * 1.1
                    )

    def get_adaptive_stats(self) -> dict:
        """Get adaptive rate limiter statistics - thread-safe"""
        with self._lock:
            base_stats = self.get_stats()

            # Calculate additional adaptive metrics
            total_requests = self._error_count + self._success_count
            error_rate = (
                self._error_count / total_requests
                if total_requests > 0 else 0.0
            )

            avg_response_time = (
                sum(self._response_times) / len(self._response_times)
                if self._response_times else 0.0
            )

            return {
                **base_stats,
                "error_count": self._error_count,
                "success_count": self._success_count,
                "error_rate": error_rate,
                "avg_response_time_ms": avg_response_time,
                "min_rps": self._min_requests_per_second,
                "max_rps": self._max_requests_per_second
            }

    def reset(self) -> None:
        """Reset all state including adaptive metrics - thread-safe"""
        with self._lock:
            super().reset()
            self._response_times.clear()
            self._error_count = 0
            self._success_count = 0
