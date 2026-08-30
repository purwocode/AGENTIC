"""
Custom Exceptions.

Consistent error handling across the framework.
"""
from __future__ import annotations


class AttackSurfaceError(Exception):
    """Base exception for all framework errors."""
    
    def __init__(self, message: str, code: str = None, details: dict = None):
        super().__init__(message)
        self.message = message
        self.code = code or "UNKNOWN_ERROR"
        self.details = details or {}
    
    def to_dict(self) -> dict:
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details
        }


# ============================================================================
# Authorization Errors
# ============================================================================

class AuthorizationError(AttackSurfaceError):
    """Raised when authorization check fails."""
    
    def __init__(self, message: str = "Authorization required"):
        super().__init__(message, code="AUTH_REQUIRED")


class SafetyGateError(AttackSurfaceError):
    """Raised when safety gate refuses a request."""
    
    def __init__(self, message: str = "Request refused by safety gate"):
        super().__init__(message, code="SAFETY_GATE_REFUSED")


# ============================================================================
# Scanner Errors
# ============================================================================

class ScannerError(AttackSurfaceError):
    """Base error for scanner issues."""
    pass


class TargetUnreachableError(ScannerError):
    """Raised when target cannot be reached."""
    
    def __init__(self, target: str, reason: str = ""):
        message = f"Cannot reach target: {target}"
        if reason:
            message += f" ({reason})"
        super().__init__(message, code="TARGET_UNREACHABLE", details={"target": target})


class WAFBlockedError(ScannerError):
    """Raised when WAF blocks requests."""
    
    def __init__(self, waf_name: str = "Unknown"):
        super().__init__(
            f"Request blocked by WAF: {waf_name}",
            code="WAF_BLOCKED",
            details={"waf": waf_name}
        )


class RateLimitError(ScannerError):
    """Raised when rate limit is hit."""
    
    def __init__(self, retry_after: int = None):
        message = "Rate limit exceeded"
        if retry_after:
            message += f", retry after {retry_after}s"
        super().__init__(message, code="RATE_LIMITED", details={"retry_after": retry_after})


class TimeoutError(ScannerError):
    """Raised when request times out."""
    
    def __init__(self, timeout: int):
        super().__init__(
            f"Request timed out after {timeout}s",
            code="TIMEOUT",
            details={"timeout": timeout}
        )


# ============================================================================
# Payload Errors
# ============================================================================

class PayloadError(AttackSurfaceError):
    """Base error for payload issues."""
    pass


class InvalidPayloadError(PayloadError):
    """Raised when payload is invalid."""
    
    def __init__(self, payload: str, reason: str = ""):
        super().__init__(
            f"Invalid payload: {reason}",
            code="INVALID_PAYLOAD",
            details={"payload": payload[:100]}
        )


class EncodingError(PayloadError):
    """Raised when payload encoding fails."""
    
    def __init__(self, encoder: str, reason: str = ""):
        super().__init__(
            f"Encoding failed with {encoder}: {reason}",
            code="ENCODING_ERROR",
            details={"encoder": encoder}
        )


# ============================================================================
# Report Errors
# ============================================================================

class ReportError(AttackSurfaceError):
    """Base error for report issues."""
    pass


class ExportError(ReportError):
    """Raised when export fails."""
    
    def __init__(self, format: str, reason: str = ""):
        super().__init__(
            f"Export to {format} failed: {reason}",
            code="EXPORT_ERROR",
            details={"format": format}
        )


# ============================================================================
# API Errors
# ============================================================================

class APIError(AttackSurfaceError):
    """Base error for API issues."""
    pass


class InvalidRequestError(APIError):
    """Raised when API request is invalid."""
    
    def __init__(self, reason: str):
        super().__init__(reason, code="INVALID_REQUEST")


class JobNotFoundError(APIError):
    """Raised when job is not found."""
    
    def __init__(self, job_id: str):
        super().__init__(
            f"Job not found: {job_id}",
            code="JOB_NOT_FOUND",
            details={"job_id": job_id}
        )


# ============================================================================
# Configuration Errors
# ============================================================================

class ConfigError(AttackSurfaceError):
    """Raised when configuration is invalid."""
    
    def __init__(self, key: str, reason: str = ""):
        super().__init__(
            f"Invalid configuration for {key}: {reason}",
            code="CONFIG_ERROR",
            details={"key": key}
        )


# ============================================================================
# Validation Errors
# ============================================================================

class ValidationError(AttackSurfaceError):
    """Raised when validation fails."""
    
    def __init__(self, field: str, reason: str):
        super().__init__(
            f"Validation failed for {field}: {reason}",
            code="VALIDATION_ERROR",
            details={"field": field}
        )


__all__ = [
    # Base
    "AttackSurfaceError",
    # Authorization
    "AuthorizationError",
    "SafetyGateError",
    # Scanner
    "ScannerError",
    "TargetUnreachableError",
    "WAFBlockedError",
    "RateLimitError",
    "TimeoutError",
    # Payload
    "PayloadError",
    "InvalidPayloadError",
    "EncodingError",
    # Report
    "ReportError",
    "ExportError",
    # API
    "APIError",
    "InvalidRequestError",
    "JobNotFoundError",
    # Config
    "ConfigError",
    # Validation
    "ValidationError",
]
