import unittest

from attack_surface.orchestrator import ZeroDayOrchestrator


class ZeroDayOrchestratorTests(unittest.TestCase):
    def test_unauthorized_request_is_refused(self) -> None:
        """Request without authorization should be refused."""
        report = ZeroDayOrchestrator().run("Buat payload exploit zero-day")

        self.assertEqual(report.status, "refused")
        self.assertEqual(report.turns, ())

    def test_authorized_request_produces_exploits(self) -> None:
        """Authorized request should produce payloads and exploits."""
        report = ZeroDayOrchestrator().run(
            "Zero-day research endpoint login internal dengan izin tertulis"
        )

        self.assertIn(report.status, ("exploit_validated", "analysis_complete"))
        self.assertGreater(len(report.turns), 0)
        self.assertIn("ZERO-DAY RESEARCH REPORT", report.final)
        self.assertIn("EXPLOIT CODE", report.final)
        self.assertIn("payload", report.final.lower())

    def test_report_contains_validated_findings(self) -> None:
        """Report should contain structured findings with PoC."""
        report = ZeroDayOrchestrator().run(
            "Zero-day research endpoint login dengan izin tertulis"
        )

        # Check findings are extracted
        self.assertGreater(len(report.findings), 0)
        
        # Check at least one finding is validated
        validated = [f for f in report.findings if f.validation_status == "validated"]
        self.assertGreater(len(validated), 0)
        
        # Check PoC is present
        for finding in validated:
            self.assertIsNotNone(finding.poc)
            self.assertTrue(finding.poc.verified)

    def test_report_contains_false_positive_checks(self) -> None:
        """Report should include false positive validation."""
        report = ZeroDayOrchestrator().run(
            "Zero-day research endpoint login dengan izin tertulis"
        )

        self.assertIn("false positive check", report.final.lower())
        self.assertIn("not a false positive", report.final.lower())
        
        for finding in report.findings:
            self.assertGreater(len(finding.false_positive_checks), 0)

    def test_all_agents_contribute_to_analysis(self) -> None:
        """All five agents should contribute."""
        report = ZeroDayOrchestrator().run(
            "Zero-day research endpoint dengan izin tertulis"
        )

        agent_names = {turn.agent for turn in report.turns}
        expected_agents = {
            "ReconAgent", 
            "VulnHunterAgent", 
            "ExploitDevAgent",
            "PoCValidatorAgent",
            "EvidenceCollectorAgent"
        }
        self.assertEqual(agent_names, expected_agents)


if __name__ == "__main__":
    unittest.main()
