"""Tests for the scanner module: WAF detection, payload encoding, and interactive validation."""
import unittest

from attack_surface.scanner import (
    WAFDetector, WAFDetectionResult, WAFSignature,
    PayloadEncoder, WAFBypasses,
    InteractiveValidator, InteractivePayload,
    HttpResponse, EndpointInfo, VulnTestResult, TechStack
)


class WAFDetectorTests(unittest.TestCase):
    """Test WAF detection functionality."""
    
    def test_detects_cloudflare_from_headers(self) -> None:
        """Should detect Cloudflare WAF from response headers."""
        headers = {"cf-ray": "abc123", "server": "cloudflare"}
        result = WAFDetector.detect_from_response(headers, "", 403, {})
        
        self.assertTrue(result.detected)
        self.assertEqual(result.waf_type, "Cloudflare")
        self.assertGreaterEqual(result.confidence, 0.8)
    
    def test_detects_aws_waf_from_headers(self) -> None:
        """Should detect AWS WAF from x-amzn headers."""
        headers = {"x-amzn-requestid": "abc123", "x-amz-cf-id": "xyz"}
        result = WAFDetector.detect_from_response(headers, "", 403, {})
        
        self.assertTrue(result.detected)
        self.assertEqual(result.waf_type, "AWS WAF")
    
    def test_detects_modsecurity_from_body(self) -> None:
        """Should detect ModSecurity from error body patterns."""
        # Use body pattern and ModSecurity header to ensure detection
        body = "Request blocked by Mod_Security rule"
        headers = {"x-mod-security": "1"}
        result = WAFDetector.detect_from_response(headers, body, 403, "")
        
        self.assertTrue(result.detected)
        self.assertEqual(result.waf_type, "ModSecurity")
    
    def test_detects_imperva_from_cookies(self) -> None:
        """Should detect Imperva/Incapsula from cookies."""
        # cookies parameter is a string, not dict
        cookies = "incap_ses_123=value; visid_incap_456=value2"
        result = WAFDetector.detect_from_response({}, "", 403, cookies)
        
        self.assertTrue(result.detected)
        self.assertIn("Imperva", result.waf_type)
    
    def test_returns_unknown_when_no_waf(self) -> None:
        """Should return Unknown when no WAF is detected."""
        result = WAFDetector.detect_from_response({}, "Normal page", 200, {})
        
        self.assertFalse(result.detected)
        self.assertEqual(result.waf_type, "Unknown")
        self.assertEqual(result.confidence, 0.0)
    
    def test_detects_captcha_in_body(self) -> None:
        """Should detect CAPTCHA challenges."""
        # The pattern looks for 'google.com/recaptcha' not 'g-recaptcha'
        body = '<script src="https://www.google.com/recaptcha/api.js"></script>'
        result = WAFDetector.detect_from_response({}, body, 200, "")
        
        # captcha_detected is a string with captcha type, not boolean
        self.assertIn("reCAPTCHA", result.captcha_detected)
    
    def test_provides_bypass_techniques(self) -> None:
        """Should provide bypass techniques for detected WAF."""
        headers = {"cf-ray": "abc123"}
        result = WAFDetector.detect_from_response(headers, "", 403, {})
        
        self.assertGreater(len(result.bypass_techniques), 0)
        self.assertIn("unicode", " ".join(result.bypass_techniques).lower())
    
    def test_get_probe_payloads_returns_list(self) -> None:
        """Should return probe payloads for WAF detection."""
        payloads = WAFDetector.get_probe_payloads()
        
        self.assertGreater(len(payloads), 0)
        self.assertTrue(any("'" in p for p in payloads))  # SQL injection
        self.assertTrue(any("<" in p for p in payloads))  # XSS
    
    def test_get_supported_wafs(self) -> None:
        """Should return list of all supported WAFs."""
        wafs = WAFDetector.get_supported_wafs()
        
        self.assertGreater(len(wafs), 10)
        self.assertIn("Cloudflare", wafs)
        self.assertIn("AWS WAF", wafs)
        self.assertIn("ModSecurity", wafs)


class PayloadEncoderTests(unittest.TestCase):
    """Test payload encoding methods for WAF bypass."""
    
    def test_double_url_encode(self) -> None:
        """Should double URL encode special characters."""
        result = PayloadEncoder.double_url_encode("'")
        self.assertEqual(result, "%2527")
    
    def test_unicode_encode(self) -> None:
        """Should unicode encode characters."""
        result = PayloadEncoder.unicode_encode("'")
        self.assertIn("\\u", result.lower())
    
    def test_html_entity_encode(self) -> None:
        """Should HTML entity encode characters."""
        result = PayloadEncoder.html_entity_encode("<")
        self.assertIn("&#", result)
    
    def test_html_entity_encode_hex(self) -> None:
        """Should HTML hex entity encode characters."""
        result = PayloadEncoder.html_entity_encode("<", use_hex=True)
        self.assertIn("&#x", result)
    
    def test_mixed_case_encode(self) -> None:
        """Should apply mixed case encoding."""
        result = PayloadEncoder.mixed_case_encode("SELECT")
        # Should have mixed case
        self.assertNotEqual(result, "SELECT")
        self.assertNotEqual(result, "select")
        self.assertEqual(result.upper(), "SELECT")
    
    def test_comment_obfuscate(self) -> None:
        """Should replace spaces with SQL comments."""
        result = PayloadEncoder.comment_obfuscate("SELECT * FROM users")
        self.assertIn("/**/", result)
        self.assertNotIn(" ", result)
    
    def test_sql_obfuscation(self) -> None:
        """Should generate SQL-specific bypass variations."""
        result = PayloadEncoder.sql_obfuscation("' OR 1=1--")
        
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 1)
    
    def test_xss_obfuscation(self) -> None:
        """Should generate XSS-specific bypass variations."""
        result = PayloadEncoder.xss_obfuscation("<script>alert(1)</script>")
        
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 1)
    
    def test_generate_bypass_variations_sqli(self) -> None:
        """Should generate multiple bypass variations for SQLi."""
        payload = "' OR 1=1--"
        result = PayloadEncoder.generate_bypass_variations(payload, "sqli")
        
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 3)
        self.assertIn(payload, result)  # Original should be included
    
    def test_generate_bypass_variations_xss(self) -> None:
        """Should generate multiple bypass variations for XSS."""
        payload = "<script>alert(1)</script>"
        result = PayloadEncoder.generate_bypass_variations(payload, "xss")
        
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 3)


class WAFBypassesTests(unittest.TestCase):
    """Test WAF-specific bypass generation."""
    
    def test_cloudflare_bypass(self) -> None:
        """Should generate Cloudflare-specific bypasses."""
        bypasses = WAFBypasses.cloudflare_bypass("' OR 1=1--")
        
        self.assertIsInstance(bypasses, list)
        self.assertGreater(len(bypasses), 0)
    
    def test_aws_waf_bypass(self) -> None:
        """Should generate AWS WAF-specific bypasses."""
        bypasses = WAFBypasses.aws_waf_bypass("' OR 1=1--")
        
        self.assertIsInstance(bypasses, list)
        self.assertGreater(len(bypasses), 0)
    
    def test_modsecurity_bypass(self) -> None:
        """Should generate ModSecurity-specific bypasses."""
        bypasses = WAFBypasses.modsecurity_bypass("' OR 1=1--")
        
        self.assertIsInstance(bypasses, list)
        self.assertGreater(len(bypasses), 0)
    
    def test_generic_bypass(self) -> None:
        """Should generate generic WAF bypasses."""
        bypasses = WAFBypasses.generic_bypass("' OR 1=1--")
        
        self.assertIsInstance(bypasses, list)
        self.assertGreater(len(bypasses), 0)
    
    def test_get_waf_specific_bypasses_cloudflare(self) -> None:
        """Should route to correct bypass method for Cloudflare."""
        bypasses = WAFBypasses.get_waf_specific_bypasses("Cloudflare", "test")
        
        self.assertIsInstance(bypasses, list)
        self.assertGreater(len(bypasses), 0)
    
    def test_get_waf_specific_bypasses_unknown(self) -> None:
        """Should return generic bypasses for unknown WAF."""
        bypasses = WAFBypasses.get_waf_specific_bypasses("UnknownWAF", "test")
        
        self.assertIsInstance(bypasses, list)
        # Should still return generic bypasses
        self.assertGreater(len(bypasses), 0)


class InteractiveValidatorTests(unittest.TestCase):
    """Test interactive payload validation."""
    
    def test_get_sqli_payloads(self) -> None:
        """Should return SQLi interactive payloads."""
        payloads = InteractiveValidator.get_sqli_payloads()
        
        self.assertGreater(len(payloads), 0)
        for p in payloads:
            self.assertIsInstance(p, InteractivePayload)
            self.assertIsNotNone(p.canary)
            self.assertIsNotNone(p.validation_type)
    
    def test_get_xss_payloads(self) -> None:
        """Should return XSS interactive payloads."""
        payloads = InteractiveValidator.get_xss_payloads()
        
        self.assertGreater(len(payloads), 0)
        # XSS payloads should have HTML tags, javascript: URI, or event handlers
        xss_indicators = ["<", "javascript:", "onmouseover", "onerror", "onload"]
        for p in payloads:
            self.assertTrue(any(ind in p.payload for ind in xss_indicators),
                          f"XSS payload missing indicator: {p.payload[:50]}")
    
    def test_get_ssti_payloads(self) -> None:
        """Should return SSTI interactive payloads."""
        payloads = InteractiveValidator.get_ssti_payloads()
        
        self.assertGreater(len(payloads), 0)
        # SSTI payloads should have math expression canaries
        for p in payloads:
            self.assertTrue(p.canary.isdigit() or p.canary.startswith("49"))
    
    def test_get_nosql_payloads(self) -> None:
        """Should return NoSQL interactive payloads."""
        payloads = InteractiveValidator.get_nosql_payloads()
        
        self.assertGreater(len(payloads), 0)
    
    def test_get_ssrf_payloads(self) -> None:
        """Should return SSRF interactive payloads."""
        payloads = InteractiveValidator.get_ssrf_payloads()
        
        self.assertGreater(len(payloads), 0)
        # SSRF payloads should target metadata endpoints
        self.assertTrue(any("169.254" in p.payload for p in payloads))
    
    def test_get_lfi_payloads(self) -> None:
        """Should return LFI interactive payloads."""
        payloads = InteractiveValidator.get_lfi_payloads()
        
        self.assertGreater(len(payloads), 0)
        # LFI payloads should have path traversal
        self.assertTrue(any(".." in p.payload for p in payloads))
    
    def test_get_xxe_payloads(self) -> None:
        """Should return XXE interactive payloads."""
        payloads = InteractiveValidator.get_xxe_payloads()
        
        self.assertGreater(len(payloads), 0)
        # XXE payloads should have DOCTYPE
        self.assertTrue(any("DOCTYPE" in p.payload for p in payloads))
    
    def test_get_rce_payloads(self) -> None:
        """Should return RCE interactive payloads."""
        payloads = InteractiveValidator.get_rce_payloads()
        
        self.assertGreater(len(payloads), 0)
    
    def test_validate_response_detects_canary(self) -> None:
        """Should detect when canary appears in response."""
        payload = InteractivePayload(
            payload="test",
            canary="UNIQUECANARY12345",
            validation_type="canary",
            expected_result="canary in body"
        )
        
        is_vuln, confidence, evidence = InteractiveValidator.validate_response(
            payload,
            "Response body contains UNIQUECANARY12345 here",
            100.0,
            200
        )
        
        self.assertTrue(is_vuln)
        self.assertGreater(confidence, 0.5)
    
    def test_validate_response_rejects_without_canary(self) -> None:
        """Should not detect vulnerability when canary is absent."""
        payload = InteractivePayload(
            payload="test",
            canary="UNIQUECANARY12345",
            validation_type="canary",
            expected_result="canary in body"
        )
        
        is_vuln, confidence, evidence = InteractiveValidator.validate_response(
            payload,
            "Normal response without any special content",
            100.0,
            200
        )
        
        self.assertFalse(is_vuln)


class TechStackTests(unittest.TestCase):
    """Test tech stack detection."""
    
    def test_techstack_creation(self) -> None:
        """Should create TechStack with detected technologies."""
        stack = TechStack(
            server="nginx",
            framework="Express",
            language="Node.js",
            database="MongoDB",
            headers={}
        )
        
        self.assertEqual(stack.server, "nginx")
        self.assertEqual(stack.framework, "Express")
        self.assertEqual(stack.database, "MongoDB")


if __name__ == "__main__":
    unittest.main()
