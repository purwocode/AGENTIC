"""
Rate Limiting Detection & Evasion Module.

Detects and evades rate limiting mechanisms:
- HTTP rate limit headers detection
- Adaptive request timing
- IP rotation support
- Request throttling
- Retry with backoff

For security research only - requires proper authorization.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Optional
from collections import deque

logger = logging.getLogger(__name__)


@dataclass
class RateLimitInfo:
    """Detected rate limit information."""
    detected: bool = False
    limit: int = 0  # Max requests
    remaining: int = 0  # Remaining requests
    reset_time: datetime = None  # When limit resets
    window_seconds: int = 0  # Rate limit window
    retry_after: int = 0  # Seconds to wait
    headers_found: list[str] = field(default_factory=list)
    detection_method: str = ""  # "headers", "status", "body"
    confidence: float = 0.0


@dataclass
class EvasionStrategy:
    """Rate limit evasion strategy."""
    name: str
    min_delay_ms: int
    max_delay_ms: int
    jitter_percent: float  # Random variance
    burst_size: int  # Requests before pause
    burst_pause_ms: int  # Pause after burst
    headers_rotate: bool  # Rotate User-Agent etc
    use_proxy_rotation: bool
    priority: int = 0  # Lower = higher priority


class RateLimitDetector:
    """
    Detects rate limiting from HTTP responses.
    
    Checks:
    - Standard rate limit headers (X-RateLimit-*, RateLimit-*)
    - Retry-After header
    - 429 Too Many Requests status
    - Response body patterns
    - Timing patterns
    """
    
    # Standard rate limit headers
    RATE_LIMIT_HEADERS = {
        # X-RateLimit standard
        "x-ratelimit-limit": "limit",
        "x-ratelimit-remaining": "remaining",
        "x-ratelimit-reset": "reset",
        "x-ratelimit-retry-after": "retry_after",
        
        # RateLimit (draft RFC)
        "ratelimit-limit": "limit",
        "ratelimit-remaining": "remaining",
        "ratelimit-reset": "reset",
        
        # Cloudflare
        "cf-ratelimit-limit": "limit",
        "cf-ratelimit-remaining": "remaining",
        "cf-ratelimit-reset": "reset",
        
        # GitHub style
        "x-github-ratelimit-limit": "limit",
        "x-github-ratelimit-remaining": "remaining",
        "x-github-ratelimit-reset": "reset",
        
        # Twitter style
        "x-rate-limit-limit": "limit",
        "x-rate-limit-remaining": "remaining",
        "x-rate-limit-reset": "reset",
        
        # Generic
        "retry-after": "retry_after",
        "x-retry-after": "retry_after",
    }
    
    # Response body patterns indicating rate limiting
    BODY_PATTERNS = [
        "rate limit",
        "too many requests",
        "request limit exceeded",
        "slow down",
        "try again later",
        "quota exceeded",
        "throttled",
        "rate exceeded",
        "api limit",
        "request quota",
    ]
    
    @classmethod
    def detect_from_response(
        cls,
        status_code: int,
        headers: dict[str, str],
        body: str = ""
    ) -> RateLimitInfo:
        """
        Detect rate limiting from HTTP response.
        
        Returns RateLimitInfo with detected limits.
        """
        info = RateLimitInfo()
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check status code
        if status_code == 429:
            info.detected = True
            info.detection_method = "status"
            info.confidence = 0.95
        elif status_code == 503:
            # Could be rate limiting or server overload
            info.detection_method = "status"
            info.confidence = 0.5
        
        # Check rate limit headers
        for header, field_type in cls.RATE_LIMIT_HEADERS.items():
            if header in headers_lower:
                value = headers_lower[header]
                info.headers_found.append(header)
                info.detected = True
                info.confidence = max(info.confidence, 0.9)
                
                if info.detection_method != "status":
                    info.detection_method = "headers"
                
                try:
                    if field_type == "limit":
                        info.limit = int(value)
                    elif field_type == "remaining":
                        info.remaining = int(value)
                    elif field_type == "reset":
                        # Could be Unix timestamp or seconds
                        reset_val = int(value)
                        if reset_val > 1000000000:  # Unix timestamp
                            info.reset_time = datetime.fromtimestamp(reset_val)
                        else:  # Seconds from now
                            info.reset_time = datetime.now() + timedelta(seconds=reset_val)
                            info.window_seconds = reset_val
                    elif field_type == "retry_after":
                        info.retry_after = int(value)
                except (ValueError, TypeError):
                    pass
        
        # Check body patterns
        if body:
            body_lower = body.lower()
            for pattern in cls.BODY_PATTERNS:
                if pattern in body_lower:
                    info.detected = True
                    if info.detection_method == "":
                        info.detection_method = "body"
                        info.confidence = max(info.confidence, 0.7)
                    break
        
        return info
    
    @classmethod
    def estimate_window(
        cls,
        responses: list[tuple[datetime, RateLimitInfo]]
    ) -> int:
        """Estimate rate limit window from response history."""
        if len(responses) < 2:
            return 60  # Default 1 minute
        
        # Find reset patterns
        resets = [r[1].reset_time for r in responses if r[1].reset_time]
        if resets:
            # Calculate average window
            windows = []
            for i in range(1, len(resets)):
                diff = (resets[i] - resets[i-1]).total_seconds()
                if 0 < diff < 3600:  # Ignore outliers
                    windows.append(diff)
            if windows:
                return int(sum(windows) / len(windows))
        
        # Check remaining patterns
        remainings = [(r[0], r[1].remaining) for r in responses if r[1].remaining > 0]
        if len(remainings) >= 2:
            # Estimate from depletion rate
            time_diff = (remainings[-1][0] - remainings[0][0]).total_seconds()
            remain_diff = remainings[0][1] - remainings[-1][1]
            if remain_diff > 0 and time_diff > 0:
                rate = remain_diff / time_diff  # requests per second
                if rate > 0:
                    return int(remainings[0][1] / rate)
        
        return 60  # Default


class RateLimitEvasion:
    """
    Rate limit evasion strategies.
    
    Implements adaptive request timing to avoid triggering rate limits.
    """
    
    # Pre-defined evasion strategies
    STRATEGIES = {
        "conservative": EvasionStrategy(
            name="conservative",
            min_delay_ms=2000,
            max_delay_ms=5000,
            jitter_percent=0.3,
            burst_size=3,
            burst_pause_ms=10000,
            headers_rotate=True,
            use_proxy_rotation=False,
            priority=1
        ),
        "moderate": EvasionStrategy(
            name="moderate",
            min_delay_ms=500,
            max_delay_ms=2000,
            jitter_percent=0.2,
            burst_size=5,
            burst_pause_ms=5000,
            headers_rotate=True,
            use_proxy_rotation=False,
            priority=2
        ),
        "aggressive": EvasionStrategy(
            name="aggressive",
            min_delay_ms=100,
            max_delay_ms=500,
            jitter_percent=0.1,
            burst_size=10,
            burst_pause_ms=2000,
            headers_rotate=True,
            use_proxy_rotation=True,
            priority=3
        ),
        "stealth": EvasionStrategy(
            name="stealth",
            min_delay_ms=5000,
            max_delay_ms=15000,
            jitter_percent=0.5,
            burst_size=1,
            burst_pause_ms=30000,
            headers_rotate=True,
            use_proxy_rotation=True,
            priority=0
        ),
    }
    
    # User-Agent rotation pool
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    ]
    
    def __init__(
        self,
        strategy: str = "moderate",
        proxies: list[str] = None,
        custom_user_agents: list[str] = None
    ):
        self.strategy = self.STRATEGIES.get(strategy, self.STRATEGIES["moderate"])
        self.proxies = proxies or []
        self.user_agents = custom_user_agents or self.USER_AGENTS
        
        self.request_count = 0
        self.last_request_time: Optional[datetime] = None
        self.blocked_until: Optional[datetime] = None
        self.current_proxy_index = 0
        self.response_history: deque[tuple[datetime, RateLimitInfo]] = deque(maxlen=100)
    
    def calculate_delay(self, rate_info: RateLimitInfo = None) -> float:
        """
        Calculate delay before next request.
        
        Returns delay in seconds.
        """
        # If we're blocked, wait until reset
        if self.blocked_until and datetime.now() < self.blocked_until:
            return (self.blocked_until - datetime.now()).total_seconds()
        
        # If rate limit info suggests waiting
        if rate_info:
            if rate_info.retry_after > 0:
                return rate_info.retry_after
            
            if rate_info.remaining == 0 and rate_info.reset_time:
                wait_time = (rate_info.reset_time - datetime.now()).total_seconds()
                if wait_time > 0:
                    return wait_time
            
            # If remaining is low, slow down
            if rate_info.remaining > 0 and rate_info.limit > 0:
                utilization = 1 - (rate_info.remaining / rate_info.limit)
                if utilization > 0.8:  # >80% used
                    # Exponential backoff based on utilization
                    multiplier = 1 + (utilization - 0.8) * 10
                    return self.strategy.max_delay_ms * multiplier / 1000
        
        # Check burst limit
        if self.request_count > 0 and self.request_count % self.strategy.burst_size == 0:
            return self.strategy.burst_pause_ms / 1000
        
        # Normal delay with jitter
        base_delay = random.randint(
            self.strategy.min_delay_ms,
            self.strategy.max_delay_ms
        )
        
        # Add jitter
        jitter_range = int(base_delay * self.strategy.jitter_percent)
        jitter = random.randint(-jitter_range, jitter_range)
        
        return max(0, (base_delay + jitter) / 1000)
    
    def get_next_headers(self) -> dict[str, str]:
        """Get rotated headers for next request."""
        headers = {}
        
        if self.strategy.headers_rotate:
            # Rotate User-Agent
            headers["User-Agent"] = random.choice(self.user_agents)
            
            # Add random accept headers
            headers["Accept"] = random.choice([
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "application/json, text/plain, */*",
                "*/*",
            ])
            
            headers["Accept-Language"] = random.choice([
                "en-US,en;q=0.9",
                "en-GB,en;q=0.9",
                "en;q=0.9",
            ])
            
            # Random cache control
            headers["Cache-Control"] = random.choice([
                "no-cache",
                "max-age=0",
                "",
            ])
        
        return {k: v for k, v in headers.items() if v}
    
    def get_next_proxy(self) -> Optional[str]:
        """Get next proxy from rotation pool."""
        if not self.proxies or not self.strategy.use_proxy_rotation:
            return None
        
        proxy = self.proxies[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
        return proxy
    
    def record_response(self, rate_info: RateLimitInfo):
        """Record response for adaptive timing."""
        self.request_count += 1
        self.last_request_time = datetime.now()
        self.response_history.append((datetime.now(), rate_info))
        
        # Update blocked status
        if rate_info.detected and rate_info.remaining == 0:
            if rate_info.reset_time:
                self.blocked_until = rate_info.reset_time
            elif rate_info.retry_after > 0:
                self.blocked_until = datetime.now() + timedelta(seconds=rate_info.retry_after)
    
    def adapt_strategy(self):
        """Adapt strategy based on response history."""
        if len(self.response_history) < 10:
            return
        
        # Calculate block rate
        recent = list(self.response_history)[-20:]
        block_rate = sum(1 for _, r in recent if r.detected and r.remaining == 0) / len(recent)
        
        # If blocked too often, switch to more conservative strategy
        if block_rate > 0.2:  # >20% blocked
            if self.strategy.name == "aggressive":
                self.strategy = self.STRATEGIES["moderate"]
                logger.info("Adapting to moderate strategy due to high block rate")
            elif self.strategy.name == "moderate":
                self.strategy = self.STRATEGIES["conservative"]
                logger.info("Adapting to conservative strategy due to high block rate")
            elif self.strategy.name == "conservative":
                self.strategy = self.STRATEGIES["stealth"]
                logger.info("Adapting to stealth strategy due to high block rate")
    
    async def wait_before_request(self, rate_info: RateLimitInfo = None):
        """Wait appropriate time before next request."""
        delay = self.calculate_delay(rate_info)
        if delay > 0:
            logger.debug(f"Rate limit evasion: waiting {delay:.2f}s")
            await asyncio.sleep(delay)


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter that learns from responses.
    
    Features:
    - Automatic rate limit detection
    - Adaptive request timing
    - Header rotation
    - Proxy rotation support
    - Backoff on rate limit hits
    """
    
    def __init__(
        self,
        initial_strategy: str = "moderate",
        proxies: list[str] = None,
        auto_adapt: bool = True
    ):
        self.detector = RateLimitDetector()
        self.evasion = RateLimitEvasion(
            strategy=initial_strategy,
            proxies=proxies
        )
        self.auto_adapt = auto_adapt
        
        # Track per-host limits
        self.host_limits: dict[str, RateLimitInfo] = {}
    
    def process_response(
        self,
        host: str,
        status_code: int,
        headers: dict[str, str],
        body: str = ""
    ) -> RateLimitInfo:
        """
        Process response and update rate limit knowledge.
        
        Returns detected rate limit info.
        """
        # Detect rate limiting
        info = self.detector.detect_from_response(status_code, headers, body)
        
        # Update host-specific limits
        if info.detected or host not in self.host_limits:
            self.host_limits[host] = info
        
        # Record for adaptive timing
        self.evasion.record_response(info)
        
        # Auto-adapt if enabled
        if self.auto_adapt:
            self.evasion.adapt_strategy()
        
        return info
    
    async def prepare_request(self, host: str = None) -> dict:
        """
        Prepare for next request.
        
        Returns dict with:
        - headers: Rotated headers
        - proxy: Next proxy (if using)
        - waited: Seconds waited
        """
        # Get any known rate limit for host
        rate_info = self.host_limits.get(host) if host else None
        
        # Wait appropriate time
        start = time.time()
        await self.evasion.wait_before_request(rate_info)
        waited = time.time() - start
        
        return {
            "headers": self.evasion.get_next_headers(),
            "proxy": self.evasion.get_next_proxy(),
            "waited": waited
        }
    
    def get_stats(self) -> dict:
        """Get rate limiting statistics."""
        return {
            "total_requests": self.evasion.request_count,
            "current_strategy": self.evasion.strategy.name,
            "hosts_tracked": len(self.host_limits),
            "blocked_until": self.evasion.blocked_until.isoformat() if self.evasion.blocked_until else None,
            "history_size": len(self.evasion.response_history)
        }


# Export classes
__all__ = [
    "RateLimitInfo",
    "EvasionStrategy",
    "RateLimitDetector",
    "RateLimitEvasion",
    "AdaptiveRateLimiter",
]
