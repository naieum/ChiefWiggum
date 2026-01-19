"""
Rate Limiter for Guardian-Agent

Ensures testing doesn't overwhelm target systems or trigger
rate limiting defenses.
"""

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
    Token bucket rate limiter with adaptive backoff.

    Prevents overwhelming target systems during testing.
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._request_times: deque = deque(maxlen=1000)
        self._current_backoff: float = 0.0
        self._last_429_time: Optional[float] = None
        self._consecutive_429s: int = 0

    def wait_if_needed(self) -> float:
        """
        Wait if necessary to maintain rate limit.

        Returns:
            float: Actual wait time in seconds
        """
        now = time.time()

        # Apply backoff if we hit rate limits
        if self._current_backoff > 0:
            wait_time = self._current_backoff
            time.sleep(wait_time)
            self._current_backoff = 0
            return wait_time

        # Clean old requests from window
        window_start = now - 1.0  # 1 second window
        while self._request_times and self._request_times[0] < window_start:
            self._request_times.popleft()

        # Check if we need to wait
        if len(self._request_times) >= self.config.requests_per_second:
            # Calculate wait time
            oldest_in_window = self._request_times[0]
            wait_time = 1.0 - (now - oldest_in_window)
            if wait_time > 0:
                time.sleep(wait_time)
                return wait_time

        return 0.0

    def record_request(self):
        """Record that a request was made"""
        self._request_times.append(time.time())

    def record_rate_limited(self):
        """Record that we received a 429 response"""
        now = time.time()
        self._consecutive_429s += 1
        self._last_429_time = now

        # Calculate exponential backoff
        backoff = min(
            self.config.backoff_factor ** self._consecutive_429s,
            self.config.max_backoff_seconds
        )
        self._current_backoff = backoff

    def record_success(self):
        """Record a successful request (no rate limit)"""
        self._consecutive_429s = 0

    def can_retry(self) -> bool:
        """Check if we should retry after rate limiting"""
        if not self.config.retry_on_429:
            return False
        return self._consecutive_429s <= self.config.max_retries

    def get_stats(self) -> dict:
        """Get current rate limiter statistics"""
        now = time.time()
        window_start = now - 1.0

        requests_in_window = sum(
            1 for t in self._request_times if t >= window_start
        )

        return {
            "requests_in_window": requests_in_window,
            "max_requests_per_second": self.config.requests_per_second,
            "current_backoff": self._current_backoff,
            "consecutive_429s": self._consecutive_429s,
            "can_continue": self.can_retry() or self._consecutive_429s == 0
        }


class AdaptiveRateLimiter(RateLimiter):
    """
    Rate limiter that adapts based on target response.

    Automatically adjusts rate based on server response times
    and error rates.
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        super().__init__(config)
        self._response_times: deque = deque(maxlen=100)
        self._error_count: int = 0
        self._success_count: int = 0

    def record_response_time(self, response_time_ms: float):
        """Record a response time for adaptive adjustment"""
        self._response_times.append(response_time_ms)

        # If average response time is increasing, slow down
        if len(self._response_times) >= 10:
            recent_avg = sum(list(self._response_times)[-10:]) / 10
            overall_avg = sum(self._response_times) / len(self._response_times)

            if recent_avg > overall_avg * 1.5:
                # Server is slowing down, reduce rate
                self.config.requests_per_second = max(
                    1.0,
                    self.config.requests_per_second * 0.8
                )

    def record_error(self):
        """Record an error response"""
        self._error_count += 1

        # If error rate is high, slow down
        total = self._error_count + self._success_count
        if total >= 10:
            error_rate = self._error_count / total
            if error_rate > 0.1:  # More than 10% errors
                self.config.requests_per_second = max(
                    1.0,
                    self.config.requests_per_second * 0.5
                )

    def record_success(self):
        """Record a successful request"""
        super().record_success()
        self._success_count += 1

        # If things are going well, gradually increase rate
        total = self._error_count + self._success_count
        if total >= 20:
            error_rate = self._error_count / total
            if error_rate < 0.05:  # Less than 5% errors
                self.config.requests_per_second = min(
                    50.0,  # Cap at 50 rps
                    self.config.requests_per_second * 1.1
                )
