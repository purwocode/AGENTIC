"""Tests for the models module."""
import unittest

from attack_surface.models import (
    ExploitPayload, ProofOfConcept, ZeroDayFinding,
    LiveScannerModel, default_models, live_scanner_models
)


class ExploitPayloadTests(unittest.TestCase):
    """Test ExploitPayload dataclass."""
    
    def test_creates_payload(self) -> None:
        """Should create exploit payload with required fields."""
        payload = ExploitPayload(
            name="SQL Auth Bypass",
            category="injection",
            payload="' OR 1=1--",
            target_component="/api/login"
        )
        
        self.assertEqual(payload.name, "SQL Auth Bypass")
        self.assertEqual(payload.category, "injection")
        self.assertEqual(payload.payload, "' OR 1=1--")
        self.assertEqual(payload.target_component, "/api/login")
    
    def test_optional_fields_have_defaults(self) -> None:
        """Optional fields should have default values."""
        payload = ExploitPayload(
            name="Test",
            category="test",
            payload="payload",
            target_component="component"
        )
        
        self.assertEqual(payload.cve_reference, "")
        self.assertEqual(payload.confidence, 0.0)
    
    def test_payload_is_frozen(self) -> None:
        """ExploitPayload should be immutable."""
        payload = ExploitPayload("Test", "test", "payload", "component")
        
        with self.assertRaises(Exception):
            payload.name = "NewName"


class ProofOfConceptTests(unittest.TestCase):
    """Test ProofOfConcept dataclass."""
    
    def test_creates_poc(self) -> None:
        """Should create PoC with required fields."""
        payload = ExploitPayload("Test", "test", "payload", "component")
        poc = ProofOfConcept(
            title="SQL Injection PoC",
            vulnerability_type="sql_injection",
            steps=("Send payload", "Observe bypass"),
            payload=payload,
            expected_result="Authentication bypass"
        )
        
        self.assertEqual(poc.title, "SQL Injection PoC")
        self.assertEqual(poc.vulnerability_type, "sql_injection")
        self.assertEqual(len(poc.steps), 2)
    
    def test_optional_fields_have_defaults(self) -> None:
        """Optional fields should have default values."""
        payload = ExploitPayload("Test", "test", "payload", "component")
        poc = ProofOfConcept(
            title="Test",
            vulnerability_type="test",
            steps=(),
            payload=payload,
            expected_result="test"
        )
        
        self.assertEqual(poc.actual_result, "")
        self.assertEqual(poc.evidence_hash, "")
        self.assertFalse(poc.verified)
    
    def test_poc_is_frozen(self) -> None:
        """ProofOfConcept should be immutable."""
        payload = ExploitPayload("Test", "test", "payload", "component")
        poc = ProofOfConcept("Title", "type", (), payload, "expected")
        
        with self.assertRaises(Exception):
            poc.title = "NewTitle"


class ZeroDayFindingTests(unittest.TestCase):
    """Test ZeroDayFinding dataclass."""
    
    def test_creates_finding(self) -> None:
        """Should create finding with required fields."""
        finding = ZeroDayFinding(
            id="VULN-001",
            title="NoSQL Injection in Login",
            severity="critical",
            vulnerability_class="injection",
            attack_vector="network"
        )
        
        self.assertEqual(finding.id, "VULN-001")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.vulnerability_class, "injection")
    
    def test_finding_can_have_payloads(self) -> None:
        """Finding should accept list of payloads."""
        payload1 = ExploitPayload("P1", "injection", "payload1", "comp1")
        payload2 = ExploitPayload("P2", "injection", "payload2", "comp2")
        
        finding = ZeroDayFinding(
            id="VULN-001",
            title="Test",
            severity="high",
            vulnerability_class="injection",
            attack_vector="network",
            payloads=[payload1, payload2]
        )
        
        self.assertEqual(len(finding.payloads), 2)
    
    def test_finding_validation_status(self) -> None:
        """Finding should track validation status."""
        finding = ZeroDayFinding(
            id="VULN-001",
            title="Test",
            severity="high",
            vulnerability_class="injection",
            attack_vector="network"
        )
        
        self.assertEqual(finding.validation_status, "pending")
        
        finding.validation_status = "validated"
        self.assertEqual(finding.validation_status, "validated")
    
    def test_finding_false_positive_checks(self) -> None:
        """Finding should track false positive checks."""
        finding = ZeroDayFinding(
            id="VULN-001",
            title="Test",
            severity="high",
            vulnerability_class="injection",
            attack_vector="network",
            false_positive_checks=("Token validation", "Baseline comparison")
        )
        
        self.assertEqual(len(finding.false_positive_checks), 2)


class LiveScannerModelTests(unittest.TestCase):
    """Test LiveScannerModel class."""
    
    def test_creates_model_with_name(self) -> None:
        """Should create model with name."""
        model = LiveScannerModel(name="test-model")
        
        self.assertEqual(model.name, "test-model")
        self.assertIsNone(model.scan_result)
    
    def test_returns_error_without_scan_result(self) -> None:
        """Should return error message when no scan result."""
        model = LiveScannerModel(name="test-model")
        
        result = model.complete("Any prompt")
        
        self.assertIn("Error", result)
        self.assertIn("No scan result", result)


class DefaultModelsTests(unittest.TestCase):
    """Test default_models function."""
    
    def test_returns_model_list(self) -> None:
        """Should return list of models."""
        models = default_models()
        
        self.assertIsInstance(models, list)
        self.assertGreater(len(models), 0)
    
    def test_models_have_names(self) -> None:
        """Each model should have a name."""
        models = default_models()
        
        for model in models:
            self.assertTrue(hasattr(model, 'name'))
            self.assertIsNotNone(model.name)


class LiveScannerModelsTests(unittest.TestCase):
    """Test live_scanner_models function."""
    
    def test_returns_model_list(self) -> None:
        """Should return list of LiveScannerModels."""
        models = live_scanner_models()
        
        self.assertIsInstance(models, list)
        self.assertEqual(len(models), 5)  # 5 specialized models
    
    def test_models_are_live_scanner_models(self) -> None:
        """All models should be LiveScannerModel instances."""
        models = live_scanner_models()
        
        for model in models:
            self.assertIsInstance(model, LiveScannerModel)
    
    def test_models_have_unique_names(self) -> None:
        """Each model should have unique name."""
        models = live_scanner_models()
        
        names = [m.name for m in models]
        self.assertEqual(len(names), len(set(names)))
    
    def test_models_have_expected_names(self) -> None:
        """Models should have expected specialized names."""
        models = live_scanner_models()
        names = {m.name for m in models}
        
        expected = {
            "recon-model",
            "vuln-hunter-model", 
            "exploit-dev-model",
            "poc-validator-model",
            "evidence-collector-model"
        }
        
        self.assertEqual(names, expected)


if __name__ == "__main__":
    unittest.main()
