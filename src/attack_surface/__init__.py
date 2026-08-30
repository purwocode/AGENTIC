"""
Attack Surface Framework - Multi-agent security research tool.

For authorized security research only.
"""

__version__ = "1.0.0"

# Core modules
from . import agents
from . import models
from . import orchestrator
from . import safety

# New modules (v0.6.0+)
from . import oob_server
from . import rate_limiter
from . import chaining
from . import reporter
from . import ai_enhancer
from . import api_server

__all__ = [
    "__version__",
    # Core
    "agents",
    "models",
    "orchestrator",
    "safety",
    # v0.6.0
    "oob_server",
    "rate_limiter",
    # v0.7.0
    "chaining",
    # v0.8.0
    "reporter",
    # v0.9.0
    "ai_enhancer",
    # v1.0.0
    "api_server",
]
