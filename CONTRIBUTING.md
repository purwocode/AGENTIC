# Developer Guide

Panduan untuk kontributor dan developer yang ingin memahami atau memodifikasi framework.

## 📁 Struktur Kode

```
src/attack_surface/
│
├── 🏗️ FOUNDATION (Infrastruktur Clean Code)
│   ├── __init__.py      # Package exports, version, convenience imports
│   ├── __main__.py      # CLI entry point
│   ├── config.py        # Centralized configuration
│   ├── base.py          # Base classes, enums, interfaces
│   ├── utils.py         # Shared utility functions
│   └── exceptions.py    # Custom exceptions hierarchy
│
├── 🎯 CORE (Komponen Utama)
│   ├── models.py        # Data models (Finding, Payload, PoC)
│   ├── safety.py        # Authorization gate
│   ├── orchestrator.py  # Main pipeline coordinator
│   └── agents.py        # Agent definitions
│
├── 🔍 SCANNER (Mesin Scanning)
│   └── scanner.py       # WAF, Tech detection, Payloads
│
├── 🧪 TESTING (Pengujian Vulnerabilitas)
│   ├── oob_server.py    # Out-of-band testing
│   ├── rate_limiter.py  # Rate limiting
│   └── chaining.py      # Vulnerability chaining
│
├── 🤖 AI (AI Enhancement)
│   └── ai_enhancer.py   # Mutation, fuzzing, learning
│
├── 📊 REPORTING (Laporan)
│   └── reporter.py      # CVSS, HTML, exporters
│
└── 🌐 API (Web Interface)
    └── api_server.py    # REST API, dashboard
```

## 🔧 Cara Menambah Fitur Baru

### 1. Menambah Scanner Baru

```python
# src/attack_surface/my_scanner.py

from attack_surface.base import BaseScanner, Result, LoggingMixin
from attack_surface.config import get_config

class MyNewScanner(BaseScanner, LoggingMixin):
    """Scanner untuk [deskripsi]."""
    
    def __init__(self):
        self.config = get_config()
    
    def get_name(self) -> str:
        return "MyNewScanner"
    
    async def scan(self, target: str, **options) -> Result:
        self.log_info(f"Scanning {target}")
        
        try:
            # Logic scanning
            findings = []
            
            return Result.ok(findings)
        except Exception as e:
            self.log_error(f"Scan failed: {e}")
            return Result.fail(str(e))
```

### 2. Menambah Exporter Baru

```python
# Di reporter.py atau file terpisah

from attack_surface.base import BaseExporter, Finding, Result

class MyExporter(BaseExporter):
    """Export ke format [nama]."""
    
    def get_format(self) -> str:
        return "my_format"
    
    def export(self, findings: list[Finding], output_path: str) -> Result:
        try:
            # Logic export
            with open(output_path, 'w') as f:
                # Write data
                pass
            return Result.ok(output_path)
        except Exception as e:
            return Result.fail(str(e))
```

### 3. Menambah Agent Baru

```python
from attack_surface.base import BaseAgent

class MyAgent(BaseAgent):
    """Agent untuk [tujuan]."""
    
    def get_role(self) -> str:
        return "MyRole"
    
    def analyze(self, context: dict) -> dict:
        # Analisis context
        return {
            "verdict": "SUPPORT",
            "evidence": "...",
            "confidence": 0.8
        }
```

## 📋 Conventions

### Naming

| Type | Convention | Example |
|------|------------|---------|
| File | snake_case | `rate_limiter.py` |
| Class | PascalCase | `RateLimitDetector` |
| Function | snake_case | `detect_waf()` |
| Constant | UPPER_SNAKE | `MAX_TIMEOUT` |
| Private | _prefix | `_internal_method()` |

### Documentation

```python
def my_function(param1: str, param2: int = 10) -> Result:
    """
    Deskripsi singkat fungsi.
    
    Deskripsi lebih detail jika perlu.
    
    Args:
        param1: Deskripsi param1
        param2: Deskripsi param2 (default: 10)
    
    Returns:
        Result dengan data atau error
    
    Raises:
        ValidationError: Jika param1 kosong
    
    Example:
        >>> result = my_function("test")
        >>> result.success
        True
    """
    pass
```

### Error Handling

```python
from attack_surface.exceptions import (
    ScannerError,
    TargetUnreachableError,
    ValidationError
)

def scan_target(url: str):
    # Validasi dulu
    if not url:
        raise ValidationError("url", "URL tidak boleh kosong")
    
    try:
        response = requests.get(url)
    except requests.ConnectionError:
        raise TargetUnreachableError(url, "Connection refused")
    except Exception as e:
        raise ScannerError(f"Unexpected error: {e}")
```

### Configuration

```python
from attack_surface.config import get_config

def my_function():
    config = get_config()
    
    # Akses config
    timeout = config.scanner.timeout
    max_payloads = config.payload.max_payloads_per_test
    
    # Jangan hardcode nilai!
    # ❌ BAD:  timeout = 10
    # ✅ GOOD: timeout = config.scanner.timeout
```

### Hasil dengan Result

```python
from attack_surface.base import Result

def process_something(data: str) -> Result:
    if not data:
        return Result.fail("Data kosong")
    
    try:
        processed = data.upper()
        return Result.ok(processed, original_length=len(data))
    except Exception as e:
        return Result.fail(str(e))

# Usage
result = process_something("hello")
if result.success:
    print(result.data)  # "HELLO"
    print(result.metadata)  # {"original_length": 5}
else:
    print(result.error)
```

## 🧪 Testing

### Struktur Test

```
tests/
├── test_scanner.py       # Unit tests untuk scanner
├── test_agents.py        # Unit tests untuk agents
├── test_models.py        # Unit tests untuk models
├── test_orchestrator.py  # Integration tests
└── conftest.py           # Shared fixtures
```

### Menulis Test

```python
# tests/test_my_module.py

import pytest
from attack_surface.my_module import MyClass

class TestMyClass:
    """Tests for MyClass."""
    
    def test_basic_functionality(self):
        """Test fungsi dasar."""
        obj = MyClass()
        result = obj.do_something("input")
        assert result.success
        assert result.data == "expected"
    
    def test_error_handling(self):
        """Test error handling."""
        obj = MyClass()
        result = obj.do_something("")
        assert not result.success
        assert "kosong" in result.error
    
    @pytest.mark.asyncio
    async def test_async_method(self):
        """Test async method."""
        obj = MyClass()
        result = await obj.async_scan("target")
        assert result.success
```

## 📦 Menambah ke Package

Setelah membuat module baru:

1. **Update `__init__.py`**:
```python
# Di __init__.py, tambah import
from . import my_new_module

# Tambah ke __all__
__all__ = [
    ...,
    "my_new_module",
]
```

2. **Update `get_module_info()`**:
```python
def get_module_info() -> dict:
    return {
        "modules": {
            ...,
            "my_category": ["my_new_module"],
        }
    }
```

3. **Update README.md** di bagian Project Structure

## 🔄 Git Workflow

```bash
# 1. Buat branch untuk fitur
git checkout -b feature/nama-fitur

# 2. Develop & test
# ... coding ...
pytest tests/

# 3. Commit dengan conventional commit
git commit -m "feat: add [deskripsi fitur]

- Added [detail 1]
- Added [detail 2]"

# 4. Push & PR
git push origin feature/nama-fitur
```

### Conventional Commits

| Prefix | Usage |
|--------|-------|
| `feat:` | Fitur baru |
| `fix:` | Bug fix |
| `docs:` | Dokumentasi |
| `refactor:` | Refactoring tanpa ubah fungsionalitas |
| `test:` | Menambah atau update tests |
| `chore:` | Maintenance tasks |

## 📊 Diagram Arsitektur

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER INPUT                                     │
│                    "python -m attack_surface [args]"                        │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            __main__.py                                      │
│                         (CLI Entry Point)                                   │
│  • Parse arguments                                                          │
│  • Load config                                                              │
│  • Initialize orchestrator                                                  │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           config.py                                         │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐       │
│  │ScannerConfig │ │  WAFConfig   │ │PayloadConfig │ │ ReportConfig │       │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘       │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           safety.py                                         │
│                      (Authorization Gate)                                   │
│  • Check keywords: "izin", "authorized", "pentest"                          │
│  • Return: ALLOW / REFUSE                                                   │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │ (if ALLOW)
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         orchestrator.py                                     │
│                      (Pipeline Coordinator)                                 │
│                                                                             │
│  Phase 1: Reconnaissance ──────┬───────────────────────────────────────►   │
│  Phase 2: WAF Detection   ─────┤                                            │
│  Phase 3: Test Selection  ─────┤  Uses: scanner.py                          │
│  Phase 4: Vulnerability   ─────┤        oob_server.py                       │
│  Phase 5: Debate          ─────┤        rate_limiter.py                     │
│  Phase 6: Report          ─────┘        chaining.py                         │
│                                         ai_enhancer.py                      │
│                                         reporter.py                         │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            OUTPUT                                           │
│  Found/session_YYYYMMDD_HHMMSS/                                             │
│  ├── REPORT.txt                                                             │
│  ├── findings.json                                                          │
│  └── exploits/                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## ❓ FAQ

**Q: Bagaimana cara menambah payload baru?**
A: Edit `PAYLOADS` dict di scanner.py atau buat file payloads terpisah yang di-import.

**Q: Bagaimana cara menambah WAF signature?**
A: Tambah entry di `WAF_SIGNATURES` di scanner.py dengan pattern detection.

**Q: Module mana yang harus saya edit untuk [X]?**
A: Lihat tabel di awal dokumen ini untuk mapping fitur ke module.

**Q: Bagaimana cara test perubahan saya?**
A: `pytest tests/ -v` untuk run semua tests, atau `pytest tests/test_xxx.py` untuk specific.
