"""Tests for ProjectDiscovery Tools integration module."""

import pytest
from unittest.mock import patch, MagicMock
import json

from attack_surface.pdtools import (
    ProjectDiscoveryTools,
    PDToolResult,
    SubdomainResult,
    PortResult,
    HttpProbeResult,
    CrawlResult,
    NucleiResult,
    CVEResult,
    get_pd_tools,
)


class TestPDToolResult:
    """Tests for PDToolResult dataclass."""
    
    def test_creation(self):
        """Test PDToolResult creation."""
        result = PDToolResult(
            tool="nuclei",
            success=True,
            output=[{"id": "test"}],
            raw_output='{"id": "test"}',
            error="",
            command="nuclei -u test"
        )
        assert result.tool == "nuclei"
        assert result.success is True
        assert result.output == [{"id": "test"}]
        
    def test_failure_result(self):
        """Test failed result."""
        result = PDToolResult(
            tool="subfinder",
            success=False,
            output=[],
            raw_output="",
            error="Command not found"
        )
        assert result.success is False
        assert result.error == "Command not found"


class TestSubdomainResult:
    """Tests for SubdomainResult dataclass."""
    
    def test_creation(self):
        """Test SubdomainResult creation."""
        result = SubdomainResult(
            subdomain="api.example.com",
            source="crtsh",
            ip="1.2.3.4"
        )
        assert result.subdomain == "api.example.com"
        assert result.source == "crtsh"
        
    def test_minimal(self):
        """Test minimal SubdomainResult."""
        result = SubdomainResult(subdomain="test.com")
        assert result.subdomain == "test.com"
        assert result.source == ""


class TestPortResult:
    """Tests for PortResult dataclass."""
    
    def test_creation(self):
        """Test PortResult creation."""
        result = PortResult(
            host="192.168.1.1",
            port=443,
            protocol="tcp",
            service="https"
        )
        assert result.host == "192.168.1.1"
        assert result.port == 443
        assert result.service == "https"


class TestHttpProbeResult:
    """Tests for HttpProbeResult dataclass."""
    
    def test_creation(self):
        """Test HttpProbeResult creation."""
        result = HttpProbeResult(
            url="https://example.com",
            status_code=200,
            title="Example Site",
            technologies=["nginx", "php"]
        )
        assert result.url == "https://example.com"
        assert result.status_code == 200
        assert "nginx" in result.technologies


class TestCrawlResult:
    """Tests for CrawlResult dataclass."""
    
    def test_creation(self):
        """Test CrawlResult creation."""
        result = CrawlResult(
            url="https://example.com/login",
            method="GET",
            depth=2
        )
        assert result.url == "https://example.com/login"
        assert result.method == "GET"


class TestNucleiResult:
    """Tests for NucleiResult dataclass."""
    
    def test_creation(self):
        """Test NucleiResult creation."""
        result = NucleiResult(
            template_id="CVE-2021-44228",
            name="Log4j RCE",
            severity="critical",
            host="https://vulnerable.com",
            matched_at="https://vulnerable.com/api",
            tags=["cve", "rce", "log4j"]
        )
        assert result.template_id == "CVE-2021-44228"
        assert result.severity == "critical"
        assert "rce" in result.tags


class TestCVEResult:
    """Tests for CVEResult dataclass."""
    
    def test_creation(self):
        """Test CVEResult creation."""
        result = CVEResult(
            cve_id="CVE-2021-44228",
            severity="critical",
            cvss_score=10.0,
            is_kev=True,
            is_poc=True
        )
        assert result.cve_id == "CVE-2021-44228"
        assert result.cvss_score == 10.0
        assert result.is_kev is True


class TestProjectDiscoveryTools:
    """Tests for ProjectDiscoveryTools class."""
    
    def test_initialization(self):
        """Test ProjectDiscoveryTools initialization."""
        with patch('shutil.which', return_value=None):
            pdt = ProjectDiscoveryTools()
            assert pdt.timeout == 300
            assert pdt.rate_limit == 150
            assert pdt.threads == 25
    
    def test_check_tools(self):
        """Test tool availability checking."""
        # Mock all tools as unavailable
        with patch('shutil.which', return_value=None):
            pdt = ProjectDiscoveryTools()
            tools = pdt.get_available_tools()
            assert tools["nuclei"] is False
            assert tools["subfinder"] is False
            
        # Mock nuclei as available
        def mock_which(name):
            return "/usr/bin/nuclei" if name == "nuclei" else None
            
        with patch('shutil.which', side_effect=mock_which):
            pdt = ProjectDiscoveryTools()
            tools = pdt.get_available_tools()
            assert tools["nuclei"] is True
            assert tools["subfinder"] is False
    
    def test_is_tool_available(self):
        """Test individual tool availability check."""
        with patch('shutil.which', return_value=None):
            pdt = ProjectDiscoveryTools()
            assert pdt.is_tool_available("nuclei") is False
            assert pdt.is_tool_available("unknown") is False
    
    @patch('subprocess.run')
    @patch('shutil.which', return_value='/usr/bin/subfinder')
    def test_discover_subdomains(self, mock_which, mock_run):
        """Test subdomain discovery."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"host":"api.example.com","source":"crtsh"}\n{"host":"www.example.com","source":"hackertarget"}',
            stderr=""
        )
        
        pdt = ProjectDiscoveryTools()
        results = pdt.discover_subdomains("example.com")
        
        assert len(results) == 2
        assert results[0].subdomain == "api.example.com"
        assert results[1].subdomain == "www.example.com"
    
    @patch('subprocess.run')
    @patch('shutil.which', return_value='/usr/bin/httpx')
    def test_probe_http(self, mock_which, mock_run):
        """Test HTTP probing."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"url":"https://example.com","status_code":200,"title":"Example"}\n',
            stderr=""
        )
        
        pdt = ProjectDiscoveryTools()
        results = pdt.probe_http(["https://example.com"])
        
        assert len(results) == 1
        assert results[0].url == "https://example.com"
        assert results[0].status_code == 200
    
    @patch('subprocess.run')
    @patch('shutil.which', return_value='/usr/bin/nuclei')
    def test_scan_vulnerabilities(self, mock_which, mock_run):
        """Test vulnerability scanning."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"template-id":"xss-reflected","info":{"name":"Reflected XSS","severity":"high"},"host":"https://test.com","matched-at":"https://test.com/search"}\n',
            stderr=""
        )
        
        pdt = ProjectDiscoveryTools()
        results = pdt.scan_vulnerabilities(["https://test.com"])
        
        assert len(results) == 1
        assert results[0].template_id == "xss-reflected"
        assert results[0].severity == "high"
    
    @patch('subprocess.run')
    @patch('shutil.which', return_value='/usr/bin/katana')
    def test_crawl(self, mock_which, mock_run):
        """Test web crawling."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"request":{"endpoint":"https://example.com/login","method":"GET"}}\n{"request":{"endpoint":"https://example.com/api","method":"GET"}}',
            stderr=""
        )
        
        pdt = ProjectDiscoveryTools()
        results = pdt.crawl(["https://example.com"])
        
        assert len(results) == 2
        assert "login" in results[0].url
    
    def test_discover_subdomains_unavailable(self):
        """Test behavior when subfinder is unavailable."""
        with patch('shutil.which', return_value=None):
            pdt = ProjectDiscoveryTools()
            results = pdt.discover_subdomains("example.com")
            assert results == []
    
    @patch('subprocess.run')
    @patch('shutil.which', return_value='/usr/bin/subfinder')
    def test_command_timeout(self, mock_which, mock_run):
        """Test command timeout handling."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="subfinder", timeout=300)
        
        pdt = ProjectDiscoveryTools()
        results = pdt.discover_subdomains("example.com")
        
        # Should return empty list on timeout
        assert results == []


class TestGetPDTools:
    """Tests for get_pd_tools convenience function."""
    
    def test_get_pd_tools(self):
        """Test convenience function."""
        with patch('shutil.which', return_value=None):
            pdt = get_pd_tools(timeout=600, rate_limit=100)
            assert pdt.timeout == 600
            assert pdt.rate_limit == 100


class TestCombinedWorkflows:
    """Tests for combined workflow methods."""
    
    @patch('subprocess.run')
    @patch('shutil.which', return_value='/usr/bin/tool')
    def test_full_recon_no_tools(self, mock_which, mock_run):
        """Test full recon when subfinder is unavailable."""
        def mock_which_fn(name):
            return None
        
        with patch('shutil.which', side_effect=mock_which_fn):
            pdt = ProjectDiscoveryTools()
            result = pdt.full_recon("example.com")
            
            # Should still return structure
            assert "domain" in result
            assert "subdomains" in result
            assert result["subdomains"] == []
    
    @patch('subprocess.run')
    def test_vuln_scan_pipeline(self, mock_run):
        """Test vulnerability scan pipeline."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"url":"https://example.com","status_code":200}\n',
            stderr=""
        )
        
        def mock_which_fn(name):
            return f"/usr/bin/{name}" if name in ["httpx", "katana", "nuclei"] else None
        
        with patch('shutil.which', side_effect=mock_which_fn):
            pdt = ProjectDiscoveryTools()
            result = pdt.vuln_scan_pipeline(["https://example.com"])
            
            assert "targets" in result
            assert "live_hosts" in result
            assert "vulnerabilities" in result


class TestIntegrationWithScanner:
    """Tests for ActiveScanner integration."""
    
    def test_scanner_pd_tools_disabled(self):
        """Test scanner with PD tools disabled."""
        from attack_surface.scanner import ActiveScanner
        
        scanner = ActiveScanner(pd_tools_enabled=False, verbose=False)
        status = scanner.get_pd_tools_status()
        assert status["enabled"] is False
    
    def test_scanner_pd_methods_exist(self):
        """Test that PD tools methods exist on scanner."""
        from attack_surface.scanner import ActiveScanner
        
        scanner = ActiveScanner(verbose=False)
        
        # Check methods exist
        assert hasattr(scanner, "pd_discover_subdomains")
        assert hasattr(scanner, "pd_scan_ports")
        assert hasattr(scanner, "pd_probe_http")
        assert hasattr(scanner, "pd_crawl")
        assert hasattr(scanner, "pd_scan_vulnerabilities")
        assert hasattr(scanner, "pd_scan_cves")
        assert hasattr(scanner, "pd_search_cves")
        assert hasattr(scanner, "pd_full_recon")
        assert hasattr(scanner, "pd_vuln_scan_pipeline")
        assert hasattr(scanner, "get_pd_tools_status")


class TestEdgeCases:
    """Tests for edge cases."""
    
    def test_empty_output(self):
        """Test handling of empty command output."""
        result = PDToolResult(
            tool="test",
            success=True,
            output=[],
            raw_output="",
            error=""
        )
        assert result.output == []
    
    def test_malformed_json_output(self):
        """Test handling of malformed JSON in output."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='not valid json\n{"valid":"json"}',
                stderr=""
            )
            
            with patch('shutil.which', return_value='/usr/bin/subfinder'):
                pdt = ProjectDiscoveryTools()
                # Internal _run_command should skip invalid JSON lines
                result = pdt._run_command(["subfinder", "-d", "test"], "subfinder")
                
                # Should only get the valid JSON
                assert len(result.output) == 1
                assert result.output[0]["valid"] == "json"
    
    def test_special_characters_in_domain(self):
        """Test handling domains with special characters."""
        with patch('shutil.which', return_value=None):
            pdt = ProjectDiscoveryTools()
            # Should not raise exception
            results = pdt.discover_subdomains("test-domain.example.com")
            assert results == []
