"""
Centralized Configuration Module.

All configurable settings in one place for easy maintenance.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import os


@dataclass
class ScannerConfig:
    """Scanner configuration."""
    timeout: int = 10
    max_retries: int = 3
    delay_between_requests: float = 0.5
    max_concurrent_requests: int = 10
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    follow_redirects: bool = True
    verify_ssl: bool = False
    max_response_size: int = 10 * 1024 * 1024  # 10MB


@dataclass
class WAFConfig:
    """WAF detection configuration."""
    enabled: bool = True
    probe_payloads: list[str] = field(default_factory=lambda: [
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "../../../etc/passwd",
    ])
    max_bypass_variations: int = 15


@dataclass
class PayloadConfig:
    """Payload configuration."""
    max_payloads_per_test: int = 50
    enable_mutations: bool = True
    mutation_count: int = 10


@dataclass
class ReportConfig:
    """Report configuration."""
    output_dir: Path = field(default_factory=lambda: Path("Found"))
    formats: list[str] = field(default_factory=lambda: ["txt", "json"])
    include_evidence: bool = True
    max_evidence_length: int = 5000


@dataclass
class APIConfig:
    """API server configuration."""
    host: str = "0.0.0.0"
    port: int = 8080
    api_key: Optional[str] = None
    max_concurrent_scans: int = 3
    cors_enabled: bool = True


@dataclass
class DebateConfig:
    """Hypothesis debate configuration."""
    enabled: bool = True
    min_confidence_threshold: float = 0.7
    require_unanimous: bool = False
    devil_advocate_weight: float = 1.5


@dataclass
class Config:
    """
    Main configuration container.
    
    Usage:
        config = Config()
        config.scanner.timeout = 30
        config.waf.enabled = False
    """
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    waf: WAFConfig = field(default_factory=WAFConfig)
    payload: PayloadConfig = field(default_factory=PayloadConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    api: APIConfig = field(default_factory=APIConfig)
    debate: DebateConfig = field(default_factory=DebateConfig)
    
    # Runtime settings
    verbose: bool = False
    debug: bool = False
    
    @classmethod
    def from_env(cls) -> "Config":
        """Create config from environment variables."""
        config = cls()
        
        # Scanner settings
        if timeout := os.getenv("ATTACK_SURFACE_TIMEOUT"):
            config.scanner.timeout = int(timeout)
        
        # API settings
        if api_key := os.getenv("ATTACK_SURFACE_API_KEY"):
            config.api.api_key = api_key
        if port := os.getenv("ATTACK_SURFACE_PORT"):
            config.api.port = int(port)
        
        # Debug mode
        config.debug = os.getenv("ATTACK_SURFACE_DEBUG", "").lower() == "true"
        
        return config


# Global default config instance
default_config = Config()


def get_config() -> Config:
    """Get the default configuration."""
    return default_config
