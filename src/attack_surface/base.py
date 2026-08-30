"""
Base Classes and Interfaces.

Common abstractions for consistency across modules.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional, TypeVar, Generic
import hashlib
import logging

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ============================================================================
# Enums
# ============================================================================

class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    @property
    def score_range(self) -> tuple[float, float]:
        """CVSS score range for severity."""
        ranges = {
            Severity.CRITICAL: (9.0, 10.0),
            Severity.HIGH: (7.0, 8.9),
            Severity.MEDIUM: (4.0, 6.9),
            Severity.LOW: (0.1, 3.9),
            Severity.INFO: (0.0, 0.0),
        }
        return ranges[self]


class Status(Enum):
    """Generic status enum."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VulnType(Enum):
    """Vulnerability types."""
    SQLI = "sql_injection"
    NOSQLI = "nosql_injection"
    XSS = "xss"
    SSRF = "ssrf"
    SSTI = "ssti"
    LFI = "lfi"
    RCE = "rce"
    XXE = "xxe"
    CSRF = "csrf"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    OPEN_REDIRECT = "open_redirect"
    CRLF = "crlf"
    CORS = "cors"
    FILE_UPLOAD = "file_upload"
    DESERIALIZATION = "deserialization"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    GRAPHQL = "graphql"
    OTHER = "other"


# ============================================================================
# Base Data Classes
# ============================================================================

@dataclass
class Evidence:
    """Evidence for a finding."""
    content: str
    hash: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    source: str = ""
    
    def __post_init__(self):
        if not self.hash:
            self.hash = hashlib.sha256(self.content.encode()).hexdigest()[:16]


@dataclass
class Finding:
    """Base finding structure."""
    id: str
    vuln_type: VulnType
    severity: Severity
    title: str
    description: str
    endpoint: str
    parameter: str = ""
    payload: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float = 0.0
    cvss_score: float = 0.0
    verified: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    metadata: dict = field(default_factory=dict)


@dataclass  
class Result(Generic[T]):
    """Generic result wrapper with error handling."""
    success: bool
    data: Optional[T] = None
    error: Optional[str] = None
    metadata: dict = field(default_factory=dict)
    
    @classmethod
    def ok(cls, data: T, **metadata) -> "Result[T]":
        return cls(success=True, data=data, metadata=metadata)
    
    @classmethod
    def fail(cls, error: str, **metadata) -> "Result[T]":
        return cls(success=False, error=error, metadata=metadata)


# ============================================================================
# Abstract Base Classes
# ============================================================================

class BaseScanner(ABC):
    """Abstract base for all scanners."""
    
    @abstractmethod
    async def scan(self, target: str, **options) -> Result:
        """Execute scan on target."""
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Get scanner name."""
        pass


class BaseDetector(ABC):
    """Abstract base for detectors (WAF, tech stack, etc.)."""
    
    @abstractmethod
    async def detect(self, target: str) -> Result:
        """Detect something on target."""
        pass


class BaseEncoder(ABC):
    """Abstract base for payload encoders."""
    
    @abstractmethod
    def encode(self, payload: str) -> str:
        """Encode a payload."""
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Get encoder name."""
        pass


class BaseExporter(ABC):
    """Abstract base for report exporters."""
    
    @abstractmethod
    def export(self, findings: list[Finding], output_path: str) -> Result:
        """Export findings to a file."""
        pass
    
    @abstractmethod
    def get_format(self) -> str:
        """Get export format name."""
        pass


class BaseAgent(ABC):
    """Abstract base for agents."""
    
    @abstractmethod
    def analyze(self, context: dict) -> dict:
        """Analyze context and return insights."""
        pass
    
    @abstractmethod
    def get_role(self) -> str:
        """Get agent role name."""
        pass


# ============================================================================
# Utility Mixins
# ============================================================================

class LoggingMixin:
    """Mixin for consistent logging."""
    
    @property
    def logger(self) -> logging.Logger:
        return logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def log_info(self, msg: str):
        self.logger.info(f"[{self.__class__.__name__}] {msg}")
    
    def log_debug(self, msg: str):
        self.logger.debug(f"[{self.__class__.__name__}] {msg}")
    
    def log_error(self, msg: str):
        self.logger.error(f"[{self.__class__.__name__}] {msg}")


class ProgressMixin:
    """Mixin for progress tracking."""
    
    _progress: float = 0.0
    _progress_callback: Optional[Callable[[float], None]] = None
    
    def set_progress_callback(self, callback: Callable[[float], None]):
        self._progress_callback = callback
    
    def update_progress(self, progress: float):
        self._progress = min(100.0, max(0.0, progress))
        if self._progress_callback:
            self._progress_callback(self._progress)


# ============================================================================
# Type Aliases
# ============================================================================

Headers = dict[str, str]
Params = dict[str, Any]
Payload = str
PayloadList = list[Payload]
ProgressCallback = Callable[[float], None]


# ============================================================================
# Constants
# ============================================================================

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
DEFAULT_TIMEOUT = 10
MAX_EVIDENCE_LENGTH = 5000


__all__ = [
    # Enums
    "Severity",
    "Status", 
    "VulnType",
    # Data classes
    "Evidence",
    "Finding",
    "Result",
    # Base classes
    "BaseScanner",
    "BaseDetector",
    "BaseEncoder",
    "BaseExporter",
    "BaseAgent",
    # Mixins
    "LoggingMixin",
    "ProgressMixin",
    # Type aliases
    "Headers",
    "Params",
    "Payload",
    "PayloadList",
    "ProgressCallback",
    # Constants
    "DEFAULT_USER_AGENT",
    "DEFAULT_TIMEOUT",
    "MAX_EVIDENCE_LENGTH",
]
