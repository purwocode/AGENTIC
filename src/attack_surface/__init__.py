"""
Attack Surface Framework - Multi-agent security research tool.

A modular, extensible framework for authorized security research.
For authorized security research only.

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                    ATTACK SURFACE v1.0.0                    │
    ├─────────────────────────────────────────────────────────────┤
    │  Foundation:   config, base, utils, exceptions              │
    │  Core:         models, safety, orchestrator, agents         │
    │  Scanner:      scanner (WAF, Tech, Payloads)                │
    │  Testing:      oob_server, rate_limiter, chaining           │
    │  AI:           ai_enhancer (mutation, fuzzing, learning)    │
    │  Reporting:    reporter (CVSS, HTML, exporters)             │
    │  API:          api_server (REST, dashboard, distributed)    │
    └─────────────────────────────────────────────────────────────┘

Usage:
    from attack_surface import Config, get_config
    from attack_surface.base import Severity, VulnType, Finding
    from attack_surface.orchestrator import ZeroDayOrchestrator
    
    config = get_config()
    config.scanner.timeout = 30
    
    orchestrator = ZeroDayOrchestrator(config=config)
    result = await orchestrator.run("https://target.com")
"""

__version__ = "1.2.0"
__author__ = "Attack Surface Team"
__license__ = "Research Only"

# ============================================================================
# Foundation Modules (Clean Code Infrastructure)
# ============================================================================
from .config import Config, get_config, default_config
from . import base
from . import utils
from . import exceptions

# ============================================================================
# Core Modules
# ============================================================================
from . import models
from . import safety
from . import orchestrator
from . import agents

# ============================================================================
# Feature Modules (v0.6.0 - v1.0.0)
# ============================================================================
# v0.6.0: OOB & Rate Limiting
from . import oob_server
from . import rate_limiter

# v0.7.0: Vulnerability Chaining
from . import chaining

# v0.8.0: Advanced Reporting
from . import reporter

# v0.9.0: AI Enhancement
from . import ai_enhancer

# v1.0.0: API & Dashboard
from . import api_server

# v1.1.0: Dynamic Payload Engine
from . import dynamic_payloads

# v1.2.0: ProjectDiscovery Tools Integration
from . import pdtools


# ============================================================================
# Convenience Re-exports
# ============================================================================
from .base import (
    Severity,
    Status,
    VulnType,
    Evidence,
    Finding,
    Result,
    BaseScanner,
    BaseAgent,
    LoggingMixin,
)

from .exceptions import (
    AttackSurfaceError,
    AuthorizationError,
    ScannerError,
    TargetUnreachableError,
    WAFBlockedError,
    RateLimitError,
)


# ============================================================================
# Public API
# ============================================================================
__all__ = [
    # Metadata
    "__version__",
    "__author__",
    "__license__",
    
    # Foundation
    "Config",
    "get_config",
    "default_config",
    "base",
    "utils",
    "exceptions",
    
    # Core
    "models",
    "safety", 
    "orchestrator",
    "agents",
    
    # Feature modules
    "oob_server",      # v0.6.0
    "rate_limiter",    # v0.6.0
    "chaining",        # v0.7.0
    "reporter",        # v0.8.0
    "ai_enhancer",     # v0.9.0
    "api_server",      # v1.0.0
    "dynamic_payloads", # v1.1.0
    "pdtools",         # v1.2.0 - ProjectDiscovery Tools
    
    # Re-exported types
    "Severity",
    "Status",
    "VulnType",
    "Evidence",
    "Finding",
    "Result",
    "BaseScanner",
    "BaseAgent",
    "LoggingMixin",
    
    # Re-exported exceptions
    "AttackSurfaceError",
    "AuthorizationError",
    "ScannerError",
    "TargetUnreachableError",
    "WAFBlockedError",
    "RateLimitError",
]


def get_version() -> str:
    """Get framework version."""
    return __version__


def get_module_info() -> dict:
    """Get information about available modules."""
    return {
        "version": __version__,
        "modules": {
            "foundation": ["config", "base", "utils", "exceptions"],
            "core": ["models", "safety", "orchestrator", "agents"],
            "scanner": ["scanner"],
            "testing": ["oob_server", "rate_limiter", "chaining"],
            "ai": ["ai_enhancer"],
            "reporting": ["reporter"],
            "api": ["api_server"],
        }
    }
