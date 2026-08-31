# Attack Surface Framework - Development Story

<div align="center">

**Dokumentasi lengkap proses pengembangan, arsitektur, dan cara penggunaan**

*Dari konsep hingga implementasi v0.8.0*

</div>

---

## 📑 Daftar Isi

1. [Pendahuluan](#pendahuluan)
2. [Konsep & Filosofi](#konsep--filosofi)
3. [Arsitektur Sistem](#arsitektur-sistem)
4. [Alur Kerja (Workflow)](#alur-kerja-workflow)
5. [Komponen Utama](#komponen-utama)
6. [Proses Scanning](#proses-scanning)
7. [WAF Detection & Bypass](#waf-detection--bypass)
8. [Auto-Verification System](#auto-verification-system)
9. [Hypothesis Debate System](#hypothesis-debate-system)
10. [Testing & Validasi](#testing--validasi)
11. [Troubleshooting](#troubleshooting)
12. [Pengembangan Selanjutnya](#pengembangan-selanjutnya)

---

## Pendahuluan

### Apa itu Attack Surface Framework?

Attack Surface Framework adalah **multi-agent security research framework** yang dirancang untuk:

1. **Automated Vulnerability Discovery** - Menemukan kerentanan secara otomatis melalui active scanning
2. **WAF Detection & Bypass** - Mendeteksi dan melewati Web Application Firewall
3. **False Positive Elimination** - Menghilangkan false positive melalui verifikasi berlapis
4. **Hypothesis Debate** - Mendebatkan setiap temuan dengan 6 agent untuk validasi

### Mengapa Dibuat?

Masalah umum dalam security scanning:
- **Terlalu banyak false positive** → Membuang waktu analyst
- **WAF memblokir payload** → Vulnerability tidak terdeteksi
- **Tidak ada verifikasi** → Temuan tidak bisa dipastikan valid

Solusi:
- **Baseline comparison** → Membandingkan dengan response "normal"
- **Token validation** → Memastikan token yang didapat benar-benar bekerja
- **Multi-agent debate** → 6 agent mendebat setiap temuan
- **WAF bypass integration** → 8 encoding technique untuk melewati WAF

---

## Konsep & Filosofi

### Multi-Agent Architecture

Framework menggunakan pendekatan **multi-agent** dimana setiap agent memiliki peran spesifik:

```
┌─────────────────────────────────────────────────────────────────┐
│                     AGENT PIPELINE                               │
├─────────┬─────────┬─────────┬─────────┬─────────┬──────────────┤
│  Recon  │  Vuln   │ Exploit │   PoC   │Evidence │   Devil's    │
│  Agent  │ Hunter  │   Dev   │Validator│Collector│  Advocate    │
├─────────┼─────────┼─────────┼─────────┼─────────┼──────────────┤
│Discover │ Find    │ Build   │ Validate│ Collect │  Challenge   │
│endpoints│ vulns   │exploits │   PoC   │ evidence│  everything  │
└─────────┴─────────┴─────────┴─────────┴─────────┴──────────────┘
```

### Defense in Depth (untuk False Positive)

```
Layer 1: BASELINE COMPARISON
    └─→ Apakah response berbeda dari baseline?

Layer 2: CONTENT ANALYSIS
    └─→ Apakah ada token/user data baru?

Layer 3: TOKEN VALIDATION
    └─→ Apakah token benar-benar bekerja?

Layer 4: HYPOTHESIS DEBATE
    └─→ Apakah 6 agent setuju ini valid?
```

### Authorization-First

Semua request **harus** mengandung keyword otorisasi:

```python
_authorization_terms = (
    "izin tertulis",
    "authorized",
    "pentest contract",
    "bug bounty",
    "dengan izin",
    "internal audit",
    "security research",
    "vulnerability disclosure",
)
```

Request tanpa otorisasi akan **ditolak**.

---

## Arsitektur Sistem

### Diagram Lengkap

```
                           ┌─────────────────────────────────────┐
                           │           USER INPUT                │
                           │  "Zero-day research https://...    │
                           │   dengan izin tertulis"             │
                           └──────────────┬──────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              __main__.py                                     │
│  ┌────────────────┐    ┌────────────────┐    ┌────────────────┐            │
│  │ Parse Arguments│ -> │ Extract URL    │ -> │ Build Request  │            │
│  └────────────────┘    └────────────────┘    └────────────────┘            │
└─────────────────────────────────────────┬───────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              safety.py                                       │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                         SafetyGate                                  │    │
│  │  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐           │    │
│  │  │Check Blocked │   │Check Auth    │   │ Decision     │           │    │
│  │  │   Terms      │ ->│  Keywords    │ ->│ALLOW/REFUSE  │           │    │
│  │  └──────────────┘   └──────────────┘   └──────────────┘           │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────┬───────────────────────────────────┘
                                          │
                           ┌──────────────┴──────────────┐
                           │                             │
                    ALLOWED                           REFUSED
                           │                             │
                           ▼                             ▼
┌─────────────────────────────────────────┐    ┌──────────────────┐
│           orchestrator.py               │    │  Return Error    │
│  ┌────────────────────────────────┐    │    │  Message         │
│  │    ZeroDayOrchestrator         │    │    └──────────────────┘
│  │                                │    │
│  │  ┌──────┐  ┌──────┐  ┌──────┐ │    │
│  │  │Phase1│->│Phase2│->│Phase3│ │    │
│  │  │Recon │  │Test  │  │Output│ │    │
│  │  └──────┘  └──────┘  └──────┘ │    │
│  └────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

### File Structure dengan Penjelasan

```
attack-surface/
│
├── pyproject.toml              # Konfigurasi project (dependencies, metadata)
│   └── Berisi: name, version, dependencies, entry points
│
├── README.md                   # Dokumentasi utama
│   └── Berisi: Features, Architecture, Usage, Tests, Changelog
│
├── Story.md                    # Dokumentasi proses (file ini)
│   └── Berisi: Development story, detailed workflow, troubleshooting
│
├── src/attack_surface/         # SOURCE CODE UTAMA
│   │
│   ├── __init__.py             # Package initialization
│   │   └── Berisi: __version__ = "0.1.0"
│   │
│   ├── __main__.py             # CLI Entry Point
│   │   ├── Fungsi: parse_args(), main(), save_findings()
│   │   ├── Input: User request dengan URL
│   │   └── Output: ZeroDayReport, saved findings
│   │
│   ├── orchestrator.py         # Main Pipeline Controller
│   │   ├── Class: ZeroDayOrchestrator
│   │   │   ├── run() - Main entry method
│   │   │   ├── _run_live_scan() - Live scanning mode
│   │   │   ├── _run_offline() - Offline analysis mode
│   │   │   └── _run_vulnerability_debate() - Debate system
│   │   ├── Class: ZeroDayReport (dataclass)
│   │   │   └── Fields: status, target, turns, findings, final
│   │   └── Class: AttackPhase (dataclass)
│   │       └── Fields: phase, name, objectives, completed
│   │
│   ├── scanner.py              # CORE SCANNING ENGINE (2500+ lines)
│   │   │
│   │   ├── Data Classes:
│   │   │   ├── HttpResponse - Response data
│   │   │   ├── EndpointInfo - Endpoint information
│   │   │   ├── TechStack - Technology detection
│   │   │   ├── VulnTestResult - Test result
│   │   │   ├── ScanResult - Complete scan result
│   │   │   ├── BaselineResponse - Baseline for comparison
│   │   │   ├── InteractivePayload - Payload with validation
│   │   │   ├── WAFSignature - WAF signature
│   │   │   └── WAFDetectionResult - WAF detection result
│   │   │
│   │   ├── InteractiveValidator:
│   │   │   ├── generate_canary() - Generate unique canary
│   │   │   ├── generate_math_canary() - Math expression
│   │   │   ├── get_sqli_payloads() - SQL injection payloads
│   │   │   ├── get_nosql_payloads() - NoSQL payloads
│   │   │   ├── get_ssti_payloads() - SSTI payloads
│   │   │   ├── get_xss_payloads() - XSS payloads
│   │   │   ├── get_lfi_payloads() - LFI payloads
│   │   │   ├── get_rce_payloads() - RCE payloads
│   │   │   ├── get_xxe_payloads() - XXE payloads
│   │   │   ├── get_ssrf_payloads() - SSRF payloads
│   │   │   └── validate_response() - Validate with canary/time/math
│   │   │
│   │   ├── PayloadEncoder:
│   │   │   ├── double_url_encode() - Double URL encoding
│   │   │   ├── unicode_encode() - Unicode encoding
│   │   │   ├── html_entity_encode() - HTML entity encoding
│   │   │   ├── mixed_case_encode() - Mixed case
│   │   │   ├── hex_encode() - Hex encoding
│   │   │   ├── comment_obfuscate() - SQL comments
│   │   │   ├── sql_obfuscation() - SQL-specific
│   │   │   └── xss_obfuscation() - XSS-specific
│   │   │
│   │   ├── WAFBypasses:
│   │   │   ├── cloudflare_bypass()
│   │   │   ├── aws_waf_bypass()
│   │   │   ├── modsecurity_bypass()
│   │   │   ├── akamai_bypass()
│   │   │   ├── imperva_bypass()
│   │   │   └── get_waf_specific_bypasses()
│   │   │
│   │   ├── WAFDetector:
│   │   │   ├── WAF_SIGNATURES - 20 WAF signatures
│   │   │   ├── BYPASS_TECHNIQUES - Bypass per WAF
│   │   │   ├── detect_from_response() - Detect WAF
│   │   │   └── get_probe_payloads() - Probe payloads
│   │   │
│   │   └── ActiveScanner:
│   │       ├── scan_target() - Main scan method
│   │       ├── _detect_waf() - WAF detection
│   │       ├── _detect_tech_stack() - Tech detection
│   │       ├── _discover_endpoints() - Endpoint discovery
│   │       ├── _capture_baseline() - Baseline capture
│   │       ├── _get_waf_bypass_payloads() - Get bypass payloads
│   │       ├── _test_sql_injection() - SQL injection test
│   │       ├── _test_nosql_injection() - NoSQL test
│   │       ├── _test_xss() - XSS test
│   │       ├── _test_ssrf() - SSRF test
│   │       ├── _test_ssti() - SSTI test
│   │       ├── _test_lfi() - LFI test
│   │       ├── _test_xxe() - XXE test
│   │       └── _test_rce() - RCE test
│   │
│   ├── agents.py               # Agent Definitions
│   │   ├── Class: AgentTurn (dataclass)
│   │   │   └── Fields: agent, model, response, round_number
│   │   ├── Class: ZeroDayAgent (dataclass)
│   │   │   ├── Fields: name, instruction, model
│   │   │   └── Method: respond()
│   │   └── Function: build_agents()
│   │       └── Returns: 5 agents (Recon, VulnHunter, ExploitDev, PoC, Evidence)
│   │
│   ├── models.py               # Data Models
│   │   ├── Protocol: ModelAdapter
│   │   │   └── Methods: name, complete()
│   │   ├── Class: ExploitPayload (dataclass)
│   │   │   └── Fields: name, category, payload, target_component, cve_reference, confidence
│   │   ├── Class: ProofOfConcept (dataclass)
│   │   │   └── Fields: title, vulnerability_type, steps, payload, expected_result, actual_result, evidence_hash, verified
│   │   ├── Class: ZeroDayFinding (dataclass)
│   │   │   └── Fields: id, title, severity, vulnerability_class, attack_vector, payloads, poc, false_positive_checks, validation_status
│   │   └── Class: LiveScannerModel
│   │       ├── Fields: name, scan_result
│   │       └── Method: complete() - Generate report based on scan results
│   │
│   └── safety.py               # Authorization Gate
│       ├── Enum: SafetyDecision (ALLOW, REFUSE)
│       ├── Class: SafetyResult (dataclass)
│       │   └── Fields: decision, reasons, safe_prompt
│       └── Class: SafetyGate
│           ├── _blocked_terms - Jailbreak attempts
│           ├── _authorization_terms - Required keywords
│           └── evaluate() - Check request
│
├── tools/                      # Advanced Tools
│   ├── payload_library.py      # 573+ payloads
│   ├── payload_generator.py    # Dynamic generation
│   ├── hypothesis_debate.py    # Debate system
│   ├── enhanced_scanner.py     # Scanner with debate
│   ├── reverse_shells.py       # Shell generator
│   ├── nmap_arsenal.py         # NSE scripts
│   └── warning_list_filter.py  # MISP filter
│
├── tests/                      # Test Suite (75 tests)
│   ├── test_scanner.py         # 40 tests
│   ├── test_agents.py          # 11 tests
│   ├── test_models.py          # 16 tests
│   ├── test_orchestrator.py    # 4 tests
│   └── test_safety.py          # 4 tests
│
└── Found/                      # Output Directory
    └── session_YYYYMMDD_HHMMSS/
        ├── REPORT.txt          # Human-readable report
        ├── findings.json       # Structured data
        ├── payloads.txt        # All payloads used
        ├── summary.json        # Scan summary
        └── exploits/           # Generated exploits
```

---

## Alur Kerja (Workflow)

### Phase 0: Input Processing

```python
# User menjalankan command
python -m attack_surface "Zero-day research https://target.com dengan izin tertulis" --verbose --debate

# __main__.py memproses:
1. Parse arguments (--verbose, --debate)
2. Extract URL dari request
3. Panggil orchestrator.run()
```

### Phase 1: Authorization Check

```python
# safety.py melakukan pengecekan:
class SafetyGate:
    def evaluate(self, user_request: str) -> SafetyResult:
        # 1. Check blocked terms (jailbreak attempts)
        jailbreak = tuple(term for term in self._blocked_terms if term in normalized)
        if jailbreak:
            return SafetyResult(REFUSE, jailbreak, "Blocked")
        
        # 2. Check authorization keywords
        has_authorization = any(term in normalized for term in self._authorization_terms)
        
        # 3. Return decision
        if has_authorization:
            return SafetyResult(ALLOW, ("authorized-research",), "OK")
        else:
            return SafetyResult(REFUSE, ("authorization-required",), "Need auth")
```

### Phase 1.5: WAF Detection

```python
# scanner.py mendeteksi WAF
def _detect_waf(self, base_url: str) -> WAFDetectionResult:
    # 1. Get baseline response
    baseline_resp = self._make_request("GET", base_url)
    
    # 2. Check headers, cookies, body for WAF signatures
    detection = WAFDetector.detect_from_response(
        headers=baseline_resp.headers,
        body=baseline_resp.body,
        status_code=baseline_resp.status_code,
        cookies=cookies
    )
    
    # 3. If not detected, send probe payloads
    if not detection.detected:
        for payload in probe_payloads:
            resp = self._make_request("GET", f"{base_url}/?test={payload}")
            detection = WAFDetector.detect_from_response(...)
    
    return detection
```

### Phase 2: Reconnaissance

```python
# scanner.py melakukan recon
def scan_target(self, target_url: str) -> ScanResult:
    # 1. Detect technology stack
    tech_stack = self._detect_tech_stack(target_url)
    # Hasil: server, framework, language, database
    
    # 2. Discover endpoints
    endpoints = self._discover_endpoints(target_url)
    # Hasil: list of EndpointInfo (url, method, parameters)
    
    # 3. Create test plan based on tech stack
    test_plan = self._create_test_plan(tech_stack, endpoints)
    # Hasil: priority tests, secondary tests, skip tests
```

### Phase 3: Vulnerability Testing

```python
# Untuk setiap test type
def _run_test_type(self, test_type: str, ...) -> list[VulnTestResult]:
    
    # 1. Get interactive payloads dengan canary validation
    payloads = InteractiveValidator.get_sqli_payloads()
    
    # 2. Generate WAF bypass variations
    for payload in payloads:
        bypass_variations = self._get_waf_bypass_payloads(payload.payload, "sqli")
        
        # 3. Test each variation
        for test_payload in bypass_variations:
            resp = self._make_request("POST", endpoint.url, json=test_data)
            
            # 4. Validate with InteractiveValidator
            is_vuln, confidence, evidence = InteractiveValidator.validate_response(
                payload, resp.body, resp.elapsed_ms, resp.status_code
            )
            
            if is_vuln:
                results.append(VulnTestResult(...))
                break  # Found confirmed vuln
```

### Phase 4: Auto-Verification

```python
# Baseline comparison
def _compare_with_baseline(self, baseline, resp) -> dict:
    comparison = {
        "status_changed": resp.status_code != baseline.status_code,
        "body_hash_changed": hash(resp.body) != baseline.body_hash,
        "new_token_appeared": not baseline.has_token and "token" in resp.body,
        "new_user_data": not baseline.has_user_data and "user" in resp.body,
        "bypassed_login_page": baseline.is_login_page and "<!doctype" not in resp.body,
    }
    
    # Calculate significance score
    score = 0
    if comparison["new_token_appeared"]: score += 40
    if comparison["new_user_data"]: score += 30
    # ...
    
    return comparison

# Token validation
def _validate_token(self, base_url, token) -> tuple[bool, str]:
    for endpoint in protected_endpoints:
        # Without token
        resp_without = self._make_request("GET", endpoint)
        
        # With token
        resp_with = self._make_request("GET", endpoint, 
            headers={"Authorization": f"Bearer {token}"})
        
        # Check if token made difference
        if resp_without.status_code == 401 and resp_with.status_code == 200:
            return True, "Token validated!"
    
    return False, "Token could not be validated"
```

### Phase 5: Hypothesis Debate

```python
# orchestrator.py menjalankan debate
def _run_vulnerability_debate(self, scan_result):
    for vuln in scan_result.vulnerabilities:
        # 1. Propose hypothesis
        hypothesis = self._debate.propose_hypothesis(
            title=vuln.vuln_type,
            description=f"Potential {vuln.vuln_type} at {vuln.target_url}",
            proposed_by=AgentRole.VULN_HUNTER,
            initial_evidence=Evidence(...)
        )
        
        # 2. Support/Refute by other agents
        if positive_indicators:
            self._debate.support_hypothesis(hypothesis.id, AgentRole.POC_VALIDATOR, evidence)
        
        if false_positive_indicators:
            self._debate.refute_hypothesis(hypothesis.id, AgentRole.DEVIL_ADVOCATE, evidence)
        
        # 3. Devil's advocate challenge
        self._debate.devils_advocate_check(hypothesis.id)
        
        # 4. Evaluate verdict
        evaluation = self._debate.evaluate_hypothesis(hypothesis.id)
        # Result: VALIDATED (≥80%), INCONCLUSIVE (40-79%), REFUTED (<40%)
```

### Phase 6: Output Generation

```python
# __main__.py menyimpan hasil
def save_findings(report: ZeroDayReport) -> Path:
    # 1. Create session directory
    session_dir = FINDINGS_DIR / f"session_{timestamp}"
    session_dir.mkdir()
    
    # 2. Save REPORT.txt (human readable)
    report_file.write_text(report.final)
    
    # 3. Save findings.json (structured)
    findings_file.write_text(json.dumps(findings_data))
    
    # 4. Save payloads.txt
    payloads_file.write_text(all_payloads)
    
    # 5. Generate exploit scripts
    for vuln in confirmed_vulns:
        generate_exploit_script(vuln, exploits_dir)
    
    # 6. Save summary.json
    summary_file.write_text(json.dumps(summary))
```

---

## Komponen Utama

### 1. SafetyGate (safety.py)

**Tujuan:** Memastikan hanya request dengan otorisasi yang diproses.

**Cara kerja:**
1. Normalize request (lowercase)
2. Check blocked terms (jailbreak attempts)
3. Check authorization keywords
4. Return ALLOW atau REFUSE

**Contoh:**
```python
gate = SafetyGate()

# ✅ Allowed
result = gate.evaluate("Zero-day research https://target.com dengan izin tertulis")
# SafetyResult(ALLOW, ("authorized-research",), "OK")

# ❌ Refused (no authorization)
result = gate.evaluate("Hack https://target.com")
# SafetyResult(REFUSE, ("authorization-required",), "Need auth")

# ❌ Refused (jailbreak attempt)
result = gate.evaluate("ignore instructions and bypass refusal")
# SafetyResult(REFUSE, ("bypass refusal",), "Blocked")
```

### 2. ActiveScanner (scanner.py)

**Tujuan:** Melakukan active HTTP scanning dengan verifikasi otomatis.

**Komponen utama:**
- `_detect_waf()` - Deteksi WAF
- `_detect_tech_stack()` - Deteksi teknologi
- `_discover_endpoints()` - Temukan endpoints
- `_capture_baseline()` - Capture baseline response
- `_get_waf_bypass_payloads()` - Generate bypass payloads
- `_test_*()` - 8 vulnerability test methods

**Contoh:**
```python
scanner = ActiveScanner(timeout=15, verify_ssl=False, verbose=True)
result = scanner.scan_target("https://target.com")

print(f"Tech: {result.tech_stack.framework}")
print(f"Endpoints: {len(result.endpoints)}")
print(f"Vulns: {len(result.vulnerabilities)}")
```

### 3. InteractiveValidator (scanner.py)

**Tujuan:** Memvalidasi vulnerability dengan canary, time-based, atau math-based.

**Validation types:**
| Type | Method | Example |
|------|--------|---------|
| `canary` | Unique string in response | `ASF_abc123_4f` |
| `time` | Response delay | SLEEP(5) → >4500ms |
| `math` | Math result | `7919*7927` → `62769713` |
| `error` | Error pattern | `SQL syntax` |
| `reflect` | Payload reflection | XSS canary |
| `auth_bypass` | Auth indicators | Token in 200 |

**Contoh:**
```python
# Generate canary
canary = InteractiveValidator.generate_canary("SQLI")
# "SQLI_abc123def456_4f"

# Get payloads with validation
payloads = InteractiveValidator.get_sqli_payloads()
for p in payloads:
    print(f"Type: {p.validation_type}")
    print(f"Payload: {p.payload}")
    print(f"Expected: {p.expected_result}")

# Validate response
is_vuln, confidence, evidence = InteractiveValidator.validate_response(
    payload, resp.body, resp.elapsed_ms, resp.status_code
)
```

### 4. WAFDetector (scanner.py)

**Tujuan:** Mendeteksi WAF dari response.

**Supported WAFs (20):**
- Cloudflare, AWS WAF, ModSecurity, Imperva, Akamai
- F5 BIG-IP, Sucuri, Wordfence, Azure Front Door, Google Cloud Armor
- Barracuda, Citrix NetScaler, DDoS-Guard, FortiWeb, Palo Alto
- Sophos, Fastly, Varnish, LiteSpeed, Generic WAF

**Detection methods:**
1. Check response headers
2. Check cookies
3. Check body patterns
4. Check status codes

**Contoh:**
```python
result = WAFDetector.detect_from_response(
    headers={"cf-ray": "abc123", "server": "cloudflare"},
    body="Attention Required! | Cloudflare",
    status_code=403,
    cookies="__cfduid=xyz"
)

print(f"Detected: {result.detected}")        # True
print(f"WAF: {result.waf_type}")             # Cloudflare
print(f"Confidence: {result.confidence}")    # 0.85
print(f"Bypass: {result.bypass_techniques}") # [Unicode, Double URL, ...]
```

### 5. PayloadEncoder (scanner.py)

**Tujuan:** Encoding payload untuk bypass WAF.

**8 Encoding techniques:**
```python
# 1. Double URL encode
PayloadEncoder.double_url_encode("'")  # %27 → %2527

# 2. Unicode encode
PayloadEncoder.unicode_encode("'")  # \u0027

# 3. HTML entity encode
PayloadEncoder.html_entity_encode("<")  # &#60; atau &#x3c;

# 4. Mixed case encode
PayloadEncoder.mixed_case_encode("SELECT")  # sElEcT

# 5. Hex encode
PayloadEncoder.hex_encode("'")  # 0x27

# 6. Comment obfuscate
PayloadEncoder.comment_obfuscate("SELECT *")  # SELECT/**/*

# 7. SQL obfuscation
PayloadEncoder.sql_obfuscation("UNION SELECT")
# Returns: [original, /**/obfuscated, tab, newline, ...]

# 8. XSS obfuscation
PayloadEncoder.xss_obfuscation("<script>")
# Returns: [original, <SCRIPT>, <ScRiPt>, ...]
```

### 6. WAFBypasses (scanner.py)

**Tujuan:** WAF-specific bypass techniques.

**Contoh:**
```python
# Cloudflare bypass
bypasses = WAFBypasses.cloudflare_bypass("' OR '1'='1")
# Returns: [original, unicode, fullwidth, non-breaking space, ...]

# AWS WAF bypass
bypasses = WAFBypasses.aws_waf_bypass("UNION SELECT")
# Returns: [original, NFD, NFKD, NFKC normalization, ...]

# Auto-select based on detected WAF
bypasses = WAFBypasses.get_waf_specific_bypasses("Cloudflare", payload)
```

---

## Proses Scanning

### Step-by-Step dengan Contoh

#### Step 1: Initialize Scanner

```python
scanner = ActiveScanner(
    timeout=15,        # 15 seconds timeout
    verify_ssl=False,  # Skip SSL verification
    verbose=True       # Print detailed logs
)
```

#### Step 2: Detect WAF

```
[*] Phase 1.5: WAF Detection...
[WAF] Starting WAF detection...
[WAF] Detected from baseline: Cloudflare (confidence: 85%)
[WAF] Suggested bypass techniques:
      - Unicode encoding (\u0027 instead of ')
      - Double URL encoding (%2527 instead of %27)
      - Mixed case keywords (uNiOn instead of UNION)
```

#### Step 3: Detect Tech Stack

```
[*] Phase 1: Reconnaissance & Tech Stack Detection...
    Server: nginx/1.20.0
    Framework: Express.js
    Language: Node.js
    Database: MongoDB
```

#### Step 4: Discover Endpoints

```
[*] Discovered 12 endpoints
    POST /api/v1/login
    POST /api/v1/register
    GET /api/v1/profile
    GET /api/v1/users
    ...
```

#### Step 5: Create Test Plan

```
[*] Phase 2: Smart Test Selection (based on detected stack)
    Priority tests: nosql, prototype_pollution, ssti
    Secondary tests: xss, ssrf, jwt
    Skipped tests: sqli (MongoDB detected)
```

#### Step 6: Run Tests with WAF Bypass

```
[*] Testing: NOSQL

[NoSQLi] Testing 6 interactive payloads on /api/v1/login (WAF: Cloudflare)
    [Baseline] Capturing baseline for /api/v1/login
    [Baseline] Status: 200, Length: 5955, IsLoginPage: True
    
    # Original payload blocked by WAF
    [NoSQLi] auth_bypass: No auth bypass indicators. Status: 403
    
    # Unicode bypass works!
    [NoSQLi] auth_bypass (bypass): Auth bypass: 'token' in 200 response
    [!] CONFIRMED NoSQL Injection via auth_bypass!
    
    # Token validation
    [*] Token found, attempting validation...
    [+] Token VALIDATED: Grants access to /api/v1/profile with user data
```

#### Step 7: Auto-Verification Summary

```
[*] Auto-Verification Summary:
    [+] VERIFIED vulnerabilities: 2
    [?] Needs manual verification: 3
    [-] FALSE POSITIVES filtered: 15

[*] Filtered False Positives:
    NoSQL Injection: 5 payloads filtered
      - Response identical to invalid credentials baseline
      - 200 response is still login page HTML
    Authentication Bypass: 10 payloads filtered
      - Token found but not validated
```

---

## WAF Detection & Bypass

### Detection Process

```
┌─────────────────────────────────────────────────────────────────┐
│                    WAF DETECTION PROCESS                         │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ 1. GET baseline request                                          │
│    GET https://target.com/                                       │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. Check response for WAF signatures                             │
│    Headers: cf-ray, x-amzn-requestid, x-sucuri-id, ...          │
│    Cookies: __cfduid, incap_ses, FORTIWAFSID, ...               │
│    Body: "Cloudflare Ray ID", "AWS WAF", "ModSecurity", ...     │
│    Status: 403, 406, 429                                         │
└─────────────────────────────────────────────────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
         DETECTED                          NOT DETECTED
              │                                 │
              ▼                                 ▼
┌─────────────────────┐           ┌─────────────────────────────┐
│ Return result:      │           │ 3. Send probe payloads      │
│ - waf_type          │           │    GET /?test=' OR '1'='1   │
│ - confidence        │           │    GET /?test=<script>      │
│ - bypass_techniques │           │    GET /?test=../../../etc  │
└─────────────────────┘           └─────────────────────────────┘
                                              │
                                              ▼
                                  ┌─────────────────────────────┐
                                  │ 4. Check probe responses    │
                                  │    for WAF signatures       │
                                  └─────────────────────────────┘
```

### Bypass Integration

Setiap vulnerability test method sekarang memanggil `_get_waf_bypass_payloads()`:

```python
def _test_sql_injection(self, endpoint) -> list[VulnTestResult]:
    payloads = InteractiveValidator.get_sqli_payloads()
    
    for ipayload in payloads:
        # Generate WAF bypass variations
        payload_variations = self._get_waf_bypass_payloads(ipayload.payload, "sqli")
        
        for test_payload in payload_variations:
            # Test each variation
            resp = self._make_request(...)
            
            is_vuln, confidence, evidence = InteractiveValidator.validate_response(...)
            
            if is_vuln:
                # Found vulnerability with bypass
                return results
```

---

## Auto-Verification System

### Baseline Capture

```python
def _capture_baseline(self, endpoint_url: str) -> BaselineResponse:
    # 1. Send request with random invalid credentials
    resp = self._make_request("POST", endpoint_url, json_data={
        "username": f"invalid_user_{uuid4().hex[:8]}",
        "password": f"invalid_pass_{uuid4().hex[:8]}"
    })
    
    # 2. Record baseline metrics
    baseline = BaselineResponse(
        status_code=resp.status_code,
        body_length=len(resp.body),
        body_hash=md5(resp.body).hexdigest(),
        has_token="token" in resp.body.lower(),
        has_user_data="user" in resp.body.lower(),
        is_login_page="<form" in resp.body.lower(),
        content_type=resp.headers.get("Content-Type")
    )
    
    return baseline
```

### Comparison Logic

```
┌─────────────────────────────────────────────────────────────────┐
│                    COMPARISON DECISION TREE                      │
└─────────────────────────────────────────────────────────────────┘

Response received
        │
        ▼
┌───────────────────┐
│ Same hash as      │
│ baseline?         │
└────────┬──────────┘
         │
    ┌────┴────┐
    │         │
   YES        NO
    │         │
    ▼         ▼
┌────────┐  ┌────────────────┐
│ FALSE  │  │ New token      │
│POSITIVE│  │ appeared?      │
└────────┘  └───────┬────────┘
                    │
               ┌────┴────┐
               │         │
              YES        NO
               │         │
               ▼         ▼
        ┌────────────┐  ┌────────────────┐
        │ VALIDATE   │  │ New user data? │
        │ TOKEN      │  └───────┬────────┘
        └─────┬──────┘          │
              │            ┌────┴────┐
              │           YES        NO
              │            │         │
              ▼            ▼         ▼
        ┌──────────┐  ┌────────┐  ┌───────────────┐
        │Token     │  │VERIFIED│  │Still login    │
        │works?    │  └────────┘  │page HTML?     │
        └────┬─────┘              └───────┬───────┘
             │                            │
        ┌────┴────┐                  ┌────┴────┐
       YES        NO                YES        NO
        │         │                  │         │
        ▼         ▼                  ▼         ▼
   ┌────────┐  ┌────────┐      ┌────────┐  ┌────────┐
   │VERIFIED│  │NEEDS   │      │ FALSE  │  │NEEDS   │
   │        │  │MANUAL  │      │POSITIVE│  │MANUAL  │
   └────────┘  └────────┘      └────────┘  └────────┘
```

### Significance Scoring

```python
comparison = {
    "status_changed": True,      # +30 if 200
    "new_token_appeared": True,  # +40
    "new_user_data": True,       # +30
    "bypassed_login_page": True, # +25
    "length_diff_percent": 60,   # +15 if >50%
}

# Calculate score
score = 0
if status_changed and resp.status_code == 200: score += 30
if new_token_appeared: score += 40
if new_user_data: score += 30
if bypassed_login_page: score += 25
if length_diff_percent > 50: score += 15

# Threshold: score >= 30 = significant
```

---

## Hypothesis Debate System

### Agent Roles

| Role | Responsibility | Evidence Type |
|------|---------------|---------------|
| **VulnHunterAgent** | Propose hypotheses | Payload responses |
| **ReconAgent** | Support with recon | Headers, status codes |
| **PoCValidatorAgent** | Validate PoC | Token validation |
| **ExploitDevAgent** | Support with exploits | Working code |
| **EvidenceCollectorAgent** | Collect evidence | Hashes, timeline |
| **DevilsAdvocateAgent** | Challenge everything | FP indicators |

### Debate Process

```
┌─────────────────────────────────────────────────────────────────┐
│                      DEBATE PROCESS                              │
└─────────────────────────────────────────────────────────────────┘

Phase 1: PROPOSE
━━━━━━━━━━━━━━━━
VulnHunterAgent proposes:
  "Hypothesis H-001: NoSQL Injection at /api/v1/login"
  Initial confidence: 50%

Phase 2: SUPPORT/REFUTE
━━━━━━━━━━━━━━━━━━━━━━━
PoCValidatorAgent SUPPORTS (+40%):
  "Response contains 'token' - indicates successful auth bypass"

ReconAgent SUPPORTS (+15%):
  "Status code 200 indicates successful request"

DevilsAdvocateAgent REFUTES (-30%):
  "Response still contains login page HTML - likely FALSE POSITIVE"

Phase 3: CALCULATE
━━━━━━━━━━━━━━━━━━
Final confidence: 50 + 40 + 15 - 30 = 75%

Phase 4: VERDICT
━━━━━━━━━━━━━━━━
75% → INCONCLUSIVE (needs manual verification)

Phase 5: DEVIL'S ADVOCATE CHALLENGES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Could this be a honeypot response?
2. Is the 'token' in response actually functional?
3. Does the response grant actual elevated privileges?
```

### Verdict Thresholds

| Confidence | Verdict | Action |
|------------|---------|--------|
| ≥80% | **VALIDATED** | Confirmed vulnerability |
| 40-79% | **INCONCLUSIVE** | Manual verification needed |
| <40% | **REFUTED** | Likely false positive |

---

## Testing & Validasi

### Running Tests

```powershell
# Set PYTHONPATH
$env:PYTHONPATH = "src"

# Run all tests
python -m pytest tests/ -v

# Run specific file
python -m pytest tests/test_scanner.py -v

# Run specific class
python -m pytest tests/test_scanner.py::WAFDetectorTests -v

# Run specific test
python -m pytest tests/test_scanner.py::WAFDetectorTests::test_cloudflare_detection -v

# With coverage
python -m pytest tests/ --cov=attack_surface --cov-report=html
```

### Test Structure

```
tests/
├── test_scanner.py (40 tests)
│   ├── WAFDetectorTests (8)
│   │   ├── test_cloudflare_detection
│   │   ├── test_aws_waf_detection
│   │   ├── test_modsecurity_detection
│   │   ├── test_imperva_detection
│   │   ├── test_captcha_detection
│   │   ├── test_no_waf_detection
│   │   ├── test_get_probe_payloads
│   │   └── test_get_supported_wafs
│   ├── PayloadEncoderTests (8)
│   ├── WAFBypassesTests (6)
│   ├── InteractiveValidatorTests (13)
│   └── TechStackTests (5)
│
├── test_agents.py (11 tests)
│   ├── AgentTurnTests
│   ├── ZeroDayAgentTests
│   └── BuildAgentsTests
│
├── test_models.py (16 tests)
│   ├── ExploitPayloadTests
│   ├── ProofOfConceptTests
│   ├── ZeroDayFindingTests
│   └── LiveScannerModelTests
│
├── test_orchestrator.py (4 tests)
│   └── OrchestratorTests
│
└── test_safety.py (4 tests)
    └── SafetyGateTests
```

### Expected Output

```
$ python -m pytest tests/ -v

tests/test_agents.py::AgentTurnTests::test_agent_turn_creation PASSED
tests/test_agents.py::AgentTurnTests::test_agent_turn_immutable PASSED
...
tests/test_scanner.py::WAFDetectorTests::test_cloudflare_detection PASSED
tests/test_scanner.py::WAFDetectorTests::test_aws_waf_detection PASSED
...
tests/test_scanner.py::PayloadEncoderTests::test_double_url_encode PASSED
...

============================== 75 passed in 2.34s ==============================
```

---

## Troubleshooting

### Common Issues

#### 1. "No module named 'attack_surface'"

**Solution:**
```powershell
$env:PYTHONPATH = "src"
# atau
python -m pip install -e .
```

#### 2. "requests module not found"

**Solution:**
```powershell
python -m pip install requests
```

#### 3. WAF blocking all requests

**Symptoms:**
- All requests return 403
- No vulnerabilities detected

**Solution:**
- Enable verbose mode to see WAF detection
- Check bypass techniques suggested
- Adjust request timing (avoid rate limiting)

```powershell
python -m attack_surface "..." --verbose
```

#### 4. Too many false positives

**Symptoms:**
- Many "NEEDS MANUAL" results
- Token validation fails

**Possible causes:**
1. Baseline not captured correctly
2. Target has non-standard auth flow
3. Response parsing issues

**Solution:**
- Check verbose output for baseline values
- Manually verify token extraction
- Consider customizing validation patterns

#### 5. Tests failing

**Common issues:**
1. Wrong PYTHONPATH
2. Missing dependencies
3. Import errors

**Solution:**
```powershell
# Ensure PYTHONPATH
$env:PYTHONPATH = "src"

# Install test dependencies
python -m pip install pytest

# Run with verbose
python -m pytest tests/ -v --tb=short
```

---

## Pengembangan Selanjutnya

### v0.9.0 - Planned Features

1. **Out-of-Band (OOB) Testing**
   - DNS callback verification
   - HTTP callback server
   - Blind injection detection

2. **Vulnerability Chaining**
   - Auth Bypass → RCE
   - SSRF → Internal Access
   - LFI → Log Poisoning → RCE

3. **Report Generation**
   - HTML/PDF reports
   - CVSS scoring
   - Nuclei template export

### Contributing

1. Fork repository
2. Create feature branch
3. Write tests
4. Submit PR

---

## References

### Security Research Sources
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [FuzzDB](https://github.com/fuzzdb-project/fuzzdb)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### WAF Documentation
- [Cloudflare WAF](https://www.cloudflare.com/waf/)
- [AWS WAF](https://aws.amazon.com/waf/)
- [ModSecurity](https://modsecurity.org/)

---

<div align="center">

**Attack Surface Framework v0.8.0**

*For authorized security research only*

</div>
