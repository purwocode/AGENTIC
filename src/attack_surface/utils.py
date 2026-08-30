"""
Utility Functions.

Shared utilities used across modules.
"""
from __future__ import annotations

import hashlib
import re
import socket
import time
from datetime import datetime
from functools import wraps
from typing import Any, Callable, Optional, TypeVar
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import logging

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ============================================================================
# URL Utilities
# ============================================================================

def normalize_url(url: str) -> str:
    """Normalize URL to consistent format."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    parsed = urlparse(url)
    # Remove trailing slash from path
    path = parsed.path.rstrip("/") or "/"
    
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def get_base_url(url: str) -> str:
    """Extract base URL (scheme + netloc)."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def get_domain(url: str) -> str:
    """Extract domain from URL."""
    parsed = urlparse(url)
    return parsed.netloc.split(":")[0]


def join_url(base: str, path: str) -> str:
    """Safely join URL parts."""
    return urljoin(base, path)


def parse_params(url: str) -> dict[str, list[str]]:
    """Parse query parameters from URL."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def build_url(base: str, path: str = "", params: dict = None) -> str:
    """Build URL with path and parameters."""
    url = join_url(base, path)
    if params:
        parsed = urlparse(url)
        query = urlencode(params, doseq=True)
        url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
    return url


def is_valid_url(url: str) -> bool:
    """Check if URL is valid."""
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https"), result.netloc])
    except Exception:
        return False


# ============================================================================
# String Utilities
# ============================================================================

def truncate(text: str, max_length: int = 500, suffix: str = "...") -> str:
    """Truncate text to max length."""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def hash_string(text: str, algorithm: str = "sha256") -> str:
    """Hash a string."""
    h = hashlib.new(algorithm)
    h.update(text.encode("utf-8", errors="ignore"))
    return h.hexdigest()


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe filesystem use."""
    # Remove invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', "_", filename)
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip(". ")
    # Limit length
    return sanitized[:200] if sanitized else "unnamed"


def extract_between(text: str, start: str, end: str) -> Optional[str]:
    """Extract text between two markers."""
    try:
        start_idx = text.index(start) + len(start)
        end_idx = text.index(end, start_idx)
        return text[start_idx:end_idx]
    except ValueError:
        return None


def mask_sensitive(text: str, visible_chars: int = 4) -> str:
    """Mask sensitive data, showing only first/last chars."""
    if len(text) <= visible_chars * 2:
        return "*" * len(text)
    return text[:visible_chars] + "***" + text[-visible_chars:]


# ============================================================================
# Time Utilities
# ============================================================================

def get_timestamp() -> str:
    """Get current timestamp string."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def format_duration(seconds: float) -> str:
    """Format duration in human readable form."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def measure_time(func: Callable[..., T]) -> Callable[..., tuple[T, float]]:
    """Decorator to measure function execution time."""
    @wraps(func)
    def wrapper(*args, **kwargs) -> tuple[T, float]:
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        return result, elapsed
    return wrapper


# ============================================================================
# Network Utilities
# ============================================================================

def is_private_ip(ip: str) -> bool:
    """Check if IP is private/internal."""
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IP."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if port is open on host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


# ============================================================================
# Data Utilities
# ============================================================================

def deep_merge(base: dict, override: dict) -> dict:
    """Deep merge two dictionaries."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def flatten_dict(d: dict, parent_key: str = "", sep: str = ".") -> dict:
    """Flatten nested dictionary."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def safe_get(d: dict, *keys, default: Any = None) -> Any:
    """Safely get nested dictionary value."""
    result = d
    for key in keys:
        try:
            result = result[key]
        except (KeyError, TypeError, IndexError):
            return default
    return result


def chunk_list(lst: list, chunk_size: int) -> list[list]:
    """Split list into chunks of specified size."""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def dedupe_preserve_order(lst: list) -> list:
    """Remove duplicates while preserving order."""
    seen = set()
    result = []
    for item in lst:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


# ============================================================================
# Retry Utilities
# ============================================================================

def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,)
) -> Callable:
    """Retry decorator with exponential backoff."""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            current_delay = delay
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        logger.debug(f"Retry {attempt + 1}/{max_attempts} after {current_delay}s: {e}")
                        time.sleep(current_delay)
                        current_delay *= backoff
            
            raise last_exception
        return wrapper
    return decorator


async def async_retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,)
):
    """Async retry decorator."""
    import asyncio
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_delay = delay
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        logger.debug(f"Async retry {attempt + 1}/{max_attempts}: {e}")
                        await asyncio.sleep(current_delay)
                        current_delay *= backoff
            
            raise last_exception
        return wrapper
    return decorator


# ============================================================================
# Validation Utilities
# ============================================================================

def validate_required(data: dict, required_fields: list[str]) -> list[str]:
    """Validate required fields exist in data. Returns list of missing fields."""
    return [f for f in required_fields if f not in data or data[f] is None]


def validate_type(value: Any, expected_type: type) -> bool:
    """Validate value is of expected type."""
    return isinstance(value, expected_type)


__all__ = [
    # URL
    "normalize_url",
    "get_base_url", 
    "get_domain",
    "join_url",
    "parse_params",
    "build_url",
    "is_valid_url",
    # String
    "truncate",
    "hash_string",
    "sanitize_filename",
    "extract_between",
    "mask_sensitive",
    # Time
    "get_timestamp",
    "format_duration",
    "measure_time",
    # Network
    "is_private_ip",
    "resolve_hostname",
    "is_port_open",
    # Data
    "deep_merge",
    "flatten_dict",
    "safe_get",
    "chunk_list",
    "dedupe_preserve_order",
    # Retry
    "retry",
    "async_retry",
    # Validation
    "validate_required",
    "validate_type",
]
