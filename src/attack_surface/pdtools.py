"""
ProjectDiscovery Tools Integration Module

Integrates the following tools:
- nuclei: Template-based vulnerability scanner
- nuclei-templates: Community vulnerability templates
- subfinder: Subdomain discovery
- httpx: HTTP probing toolkit
- cvemap/vulnx: CVE database exploration
- katana: Web crawler/spider
- naabu: Port scanner

All tools are executed via subprocess and require installation.
Install: go install github.com/projectdiscovery/<tool>@latest
"""

import json
import subprocess
import shutil
import tempfile
import os
import re
from dataclasses import dataclass, field
from typing import Optional, Any
from pathlib import Path


@dataclass
class PDToolResult:
    """Result from ProjectDiscovery tool execution."""
    tool: str
    success: bool
    output: list[dict]
    raw_output: str
    error: str = ""
    command: str = ""


@dataclass
class SubdomainResult:
    """Discovered subdomain information."""
    subdomain: str
    source: str = ""
    ip: str = ""


@dataclass 
class PortResult:
    """Discovered port information."""
    host: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""


@dataclass
class HttpProbeResult:
    """HTTP probe result."""
    url: str
    status_code: int = 0
    title: str = ""
    content_length: int = 0
    technologies: list[str] = field(default_factory=list)
    webserver: str = ""
    content_type: str = ""
    response_time: float = 0.0
    cdn: str = ""


@dataclass
class CrawlResult:
    """Web crawl result."""
    url: str
    method: str = "GET"
    source: str = ""
    depth: int = 0
    parameters: list[str] = field(default_factory=list)


@dataclass
class NucleiResult:
    """Nuclei vulnerability scan result."""
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    reference: list[str] = field(default_factory=list)
    curl_command: str = ""
    extracted_results: list[str] = field(default_factory=list)


@dataclass
class CVEResult:
    """CVE information result."""
    cve_id: str
    severity: str = ""
    cvss_score: float = 0.0
    description: str = ""
    affected_products: list[str] = field(default_factory=list)
    is_kev: bool = False
    is_poc: bool = False
    is_template: bool = False
    references: list[str] = field(default_factory=list)


class ProjectDiscoveryTools:
    """
    Wrapper for ProjectDiscovery security tools.
    
    These tools must be installed separately:
        go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        go install github.com/projectdiscovery/httpx/cmd/httpx@latest
        go install github.com/projectdiscovery/katana/cmd/katana@latest
        go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
        go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest
    """
    
    def __init__(
        self,
        timeout: int = 300,
        rate_limit: int = 150,
        threads: int = 25,
        verbose: bool = False,
        proxy: str | None = None,
        nuclei_templates_path: str | None = None
    ):
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.threads = threads
        self.verbose = verbose
        self.proxy = proxy
        self.nuclei_templates_path = nuclei_templates_path or self._get_default_templates_path()
        
        # Check tool availability
        self._available_tools = self._check_tools()
    
    def _get_default_templates_path(self) -> str:
        """Get default nuclei templates path."""
        home = Path.home()
        default_path = home / "nuclei-templates"
        if default_path.exists():
            return str(default_path)
        # Check common locations
        for path in [
            home / ".local" / "nuclei-templates",
            Path("/opt/nuclei-templates"),
            Path("C:/nuclei-templates"),
        ]:
            if path.exists():
                return str(path)
        return str(default_path)
    
    def _check_tools(self) -> dict[str, bool]:
        """Check which tools are available."""
        tools = {
            "nuclei": shutil.which("nuclei") is not None,
            "subfinder": shutil.which("subfinder") is not None,
            "httpx": shutil.which("httpx") is not None,
            "katana": shutil.which("katana") is not None,
            "naabu": shutil.which("naabu") is not None,
            "vulnx": shutil.which("vulnx") is not None,
        }
        return tools
    
    def get_available_tools(self) -> dict[str, bool]:
        """Return dict of tool availability."""
        return self._available_tools.copy()
    
    def is_tool_available(self, tool: str) -> bool:
        """Check if specific tool is available."""
        return self._available_tools.get(tool, False)
    
    def _run_command(
        self,
        cmd: list[str],
        tool_name: str,
        input_data: str | None = None,
        timeout: int | None = None
    ) -> PDToolResult:
        """Execute command and capture output."""
        timeout = timeout or self.timeout
        command_str = " ".join(cmd)
        
        try:
            result = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Parse JSON lines output
            output = []
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    try:
                        output.append(json.loads(line))
                    except json.JSONDecodeError:
                        # Non-JSON output line
                        pass
            
            return PDToolResult(
                tool=tool_name,
                success=result.returncode == 0,
                output=output,
                raw_output=result.stdout,
                error=result.stderr,
                command=command_str
            )
            
        except subprocess.TimeoutExpired:
            return PDToolResult(
                tool=tool_name,
                success=False,
                output=[],
                raw_output="",
                error=f"Command timed out after {timeout}s",
                command=command_str
            )
        except Exception as e:
            return PDToolResult(
                tool=tool_name,
                success=False,
                output=[],
                raw_output="",
                error=str(e),
                command=command_str
            )
    
    # ==================== SUBFINDER: Subdomain Discovery ====================
    
    def discover_subdomains(
        self,
        domain: str,
        sources: list[str] | None = None,
        exclude_sources: list[str] | None = None,
        recursive: bool = False,
        all_sources: bool = False,
        timeout: int | None = None
    ) -> list[SubdomainResult]:
        """
        Discover subdomains using subfinder.
        
        Args:
            domain: Target domain
            sources: Specific sources to use
            exclude_sources: Sources to exclude
            recursive: Use recursive-capable sources only
            all_sources: Use all available sources (slower)
            timeout: Custom timeout
            
        Returns:
            List of discovered subdomains
        """
        if not self.is_tool_available("subfinder"):
            return []
        
        cmd = ["subfinder", "-d", domain, "-json", "-silent"]
        
        if sources:
            cmd.extend(["-s", ",".join(sources)])
        if exclude_sources:
            cmd.extend(["-es", ",".join(exclude_sources)])
        if recursive:
            cmd.append("-recursive")
        if all_sources:
            cmd.append("-all")
        if self.proxy:
            cmd.extend(["-proxy", self.proxy])
        
        result = self._run_command(cmd, "subfinder", timeout=timeout)
        
        subdomains = []
        for item in result.output:
            subdomains.append(SubdomainResult(
                subdomain=item.get("host", item.get("subdomain", "")),
                source=item.get("source", ""),
                ip=item.get("ip", "")
            ))
        
        # Also parse raw output for non-JSON mode
        if not subdomains and result.raw_output:
            for line in result.raw_output.strip().split("\n"):
                line = line.strip()
                if line and "." in line:
                    subdomains.append(SubdomainResult(subdomain=line))
        
        return subdomains
    
    # ==================== NAABU: Port Scanner ====================
    
    def scan_ports(
        self,
        targets: list[str],
        ports: str = "top-100",
        scan_type: str = "c",  # c=CONNECT, s=SYN
        service_detection: bool = False,
        service_version: bool = False,
        exclude_cdn: bool = True,
        timeout: int | None = None
    ) -> list[PortResult]:
        """
        Scan ports using naabu.
        
        Args:
            targets: List of hosts/IPs/CIDRs
            ports: Port specification (80,443 or top-100 or 1-65535)
            scan_type: Scan type (c=CONNECT, s=SYN)
            service_detection: Identify services by port number
            service_version: Detect service versions (requires nmap probes)
            exclude_cdn: Skip full scan for CDN/WAF IPs
            timeout: Custom timeout
            
        Returns:
            List of discovered ports
        """
        if not self.is_tool_available("naabu"):
            return []
        
        cmd = ["naabu", "-json", "-silent"]
        
        # Handle ports
        if ports == "top-100":
            cmd.extend(["-top-ports", "100"])
        elif ports == "top-1000":
            cmd.extend(["-top-ports", "1000"])
        elif ports == "full":
            cmd.extend(["-p", "-"])
        else:
            cmd.extend(["-p", ports])
        
        cmd.extend(["-s", scan_type])
        cmd.extend(["-rate", str(self.rate_limit)])
        cmd.extend(["-c", str(self.threads)])
        
        if service_detection:
            cmd.append("-sD")
        if service_version:
            cmd.append("-sV")
        if exclude_cdn:
            cmd.append("-ec")
        if self.proxy:
            cmd.extend(["-proxy", self.proxy])
        
        # Write targets to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("\n".join(targets))
            targets_file = f.name
        
        try:
            cmd.extend(["-l", targets_file])
            result = self._run_command(cmd, "naabu", timeout=timeout)
        finally:
            os.unlink(targets_file)
        
        ports_list = []
        for item in result.output:
            ports_list.append(PortResult(
                host=item.get("host", item.get("ip", "")),
                port=item.get("port", 0),
                protocol=item.get("protocol", "tcp"),
                service=item.get("service", ""),
                version=item.get("version", "")
            ))
        
        return ports_list
    
    # ==================== HTTPX: HTTP Probing ====================
    
    def probe_http(
        self,
        targets: list[str],
        follow_redirects: bool = True,
        tech_detect: bool = True,
        status_code: bool = True,
        title: bool = True,
        web_server: bool = True,
        content_length: bool = True,
        screenshot: bool = False,
        ports: list[int] | None = None,
        paths: list[str] | None = None,
        timeout: int | None = None
    ) -> list[HttpProbeResult]:
        """
        Probe HTTP services using httpx.
        
        Args:
            targets: List of URLs/hosts to probe
            follow_redirects: Follow HTTP redirects
            tech_detect: Enable technology detection
            status_code: Include status code
            title: Include page title
            web_server: Include web server info
            content_length: Include content length
            screenshot: Take screenshots (requires headless)
            ports: Custom ports to probe
            paths: Custom paths to test
            timeout: Custom timeout
            
        Returns:
            List of HTTP probe results
        """
        if not self.is_tool_available("httpx"):
            return []
        
        cmd = ["httpx", "-json", "-silent"]
        
        if follow_redirects:
            cmd.append("-fr")
        if tech_detect:
            cmd.append("-td")
        if status_code:
            cmd.append("-sc")
        if title:
            cmd.append("-title")
        if web_server:
            cmd.append("-server")
        if content_length:
            cmd.append("-cl")
        if screenshot:
            cmd.append("-ss")
        
        cmd.extend(["-t", str(self.threads)])
        cmd.extend(["-rl", str(self.rate_limit)])
        cmd.extend(["-timeout", str(self.timeout // 1000 if self.timeout > 1000 else 10)])
        
        if ports:
            cmd.extend(["-ports", ",".join(map(str, ports))])
        if paths:
            cmd.extend(["-path", ",".join(paths)])
        if self.proxy:
            cmd.extend(["-proxy", self.proxy])
        
        # Pipe targets via stdin
        input_data = "\n".join(targets)
        result = self._run_command(cmd, "httpx", input_data=input_data, timeout=timeout)
        
        probes = []
        for item in result.output:
            probes.append(HttpProbeResult(
                url=item.get("url", item.get("input", "")),
                status_code=item.get("status_code", item.get("status-code", 0)),
                title=item.get("title", ""),
                content_length=item.get("content_length", item.get("content-length", 0)),
                technologies=item.get("tech", item.get("technologies", [])),
                webserver=item.get("webserver", item.get("server", "")),
                content_type=item.get("content_type", item.get("content-type", "")),
                response_time=item.get("response_time", item.get("time", 0.0)),
                cdn=item.get("cdn_name", item.get("cdn", ""))
            ))
        
        return probes
    
    # ==================== KATANA: Web Crawler ====================
    
    def crawl(
        self,
        targets: list[str],
        depth: int = 3,
        js_crawl: bool = True,
        headless: bool = False,
        scope: str = "rdn",  # rdn, fqdn, dn
        form_fill: bool = False,
        known_files: bool = True,
        timeout: int | None = None,
        max_duration: str = "10m"
    ) -> list[CrawlResult]:
        """
        Crawl websites using katana.
        
        Args:
            targets: List of URLs to crawl
            depth: Maximum crawl depth
            js_crawl: Parse JavaScript files
            headless: Use headless browser
            scope: Crawl scope (rdn=root domain, fqdn=subdomain, dn=domain keyword)
            form_fill: Enable automatic form filling
            known_files: Crawl robots.txt and sitemap.xml
            timeout: Custom timeout
            max_duration: Maximum crawl duration (e.g., "10m", "1h")
            
        Returns:
            List of discovered URLs
        """
        if not self.is_tool_available("katana"):
            return []
        
        cmd = ["katana", "-jsonl", "-silent"]
        
        cmd.extend(["-d", str(depth)])
        cmd.extend(["-fs", scope])
        cmd.extend(["-c", str(self.threads)])
        cmd.extend(["-rl", str(self.rate_limit)])
        cmd.extend(["-ct", max_duration])
        
        if js_crawl:
            cmd.append("-jc")
        if headless:
            cmd.extend(["-hl", "-nos"])  # headless + no-sandbox
        if form_fill:
            cmd.append("-aff")
        if known_files:
            cmd.extend(["-kf", "all"])
        if self.proxy:
            cmd.extend(["-proxy", self.proxy])
        
        # Pipe targets via stdin
        input_data = "\n".join(targets)
        result = self._run_command(cmd, "katana", input_data=input_data, timeout=timeout)
        
        crawl_results = []
        seen_urls = set()
        
        for item in result.output:
            url = item.get("request", {}).get("endpoint", item.get("url", ""))
            if url and url not in seen_urls:
                seen_urls.add(url)
                crawl_results.append(CrawlResult(
                    url=url,
                    method=item.get("request", {}).get("method", "GET"),
                    source=item.get("source", ""),
                    depth=item.get("depth", 0)
                ))
        
        # Parse raw output for non-JSON lines
        for line in result.raw_output.strip().split("\n"):
            line = line.strip()
            if line.startswith("http") and line not in seen_urls:
                seen_urls.add(line)
                crawl_results.append(CrawlResult(url=line))
        
        return crawl_results
    
    # ==================== NUCLEI: Vulnerability Scanner ====================
    
    def scan_vulnerabilities(
        self,
        targets: list[str],
        templates: list[str] | None = None,
        template_tags: list[str] | None = None,
        severity: list[str] | None = None,
        exclude_tags: list[str] | None = None,
        new_templates: bool = False,
        automatic_scan: bool = False,
        headless: bool = False,
        timeout: int | None = None
    ) -> list[NucleiResult]:
        """
        Scan for vulnerabilities using nuclei.
        
        Args:
            targets: List of URLs to scan
            templates: Specific template files/dirs
            template_tags: Filter templates by tags (e.g., cve, rce, sqli)
            severity: Filter by severity (critical, high, medium, low, info)
            exclude_tags: Tags to exclude
            new_templates: Only run newly added templates
            automatic_scan: Use automatic web scan
            headless: Enable headless browser
            timeout: Custom timeout
            
        Returns:
            List of vulnerability findings
        """
        if not self.is_tool_available("nuclei"):
            return []
        
        cmd = ["nuclei", "-jsonl", "-silent", "-nc"]  # nc = no-color
        
        if templates:
            for t in templates:
                cmd.extend(["-t", t])
        elif self.nuclei_templates_path and os.path.exists(self.nuclei_templates_path):
            cmd.extend(["-t", self.nuclei_templates_path])
        
        if template_tags:
            cmd.extend(["-tags", ",".join(template_tags)])
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
        if exclude_tags:
            cmd.extend(["-etags", ",".join(exclude_tags)])
        if new_templates:
            cmd.append("-nt")
        if automatic_scan:
            cmd.append("-as")
        if headless:
            cmd.append("-headless")
        
        cmd.extend(["-rl", str(self.rate_limit)])
        cmd.extend(["-c", str(self.threads)])
        
        if self.proxy:
            cmd.extend(["-proxy", self.proxy])
        
        # Pipe targets via stdin
        input_data = "\n".join(targets)
        result = self._run_command(cmd, "nuclei", input_data=input_data, timeout=timeout)
        
        findings = []
        for item in result.output:
            info = item.get("info", {})
            findings.append(NucleiResult(
                template_id=item.get("template-id", item.get("templateID", "")),
                name=info.get("name", ""),
                severity=info.get("severity", "unknown"),
                host=item.get("host", item.get("matched-at", "")),
                matched_at=item.get("matched-at", item.get("matched", "")),
                description=info.get("description", ""),
                tags=info.get("tags", []),
                reference=info.get("reference", []),
                curl_command=item.get("curl-command", ""),
                extracted_results=item.get("extracted-results", [])
            ))
        
        return findings
    
    def scan_cves(
        self,
        targets: list[str],
        cve_ids: list[str] | None = None,
        year: int | None = None,
        timeout: int | None = None
    ) -> list[NucleiResult]:
        """
        Scan for specific CVEs using nuclei.
        
        Args:
            targets: List of URLs to scan
            cve_ids: Specific CVE IDs to test
            year: Test CVEs from specific year
            timeout: Custom timeout
            
        Returns:
            List of CVE findings
        """
        tags = ["cve"]
        if year:
            tags.append(f"cve{year}")
        
        templates = []
        if cve_ids:
            # Search for specific CVE templates
            for cve_id in cve_ids:
                cve_lower = cve_id.lower().replace("-", "_")
                potential_paths = [
                    f"{self.nuclei_templates_path}/cves/{cve_id}.yaml",
                    f"{self.nuclei_templates_path}/http/cves/{cve_id}.yaml",
                ]
                for path in potential_paths:
                    if os.path.exists(path):
                        templates.append(path)
        
        return self.scan_vulnerabilities(
            targets=targets,
            templates=templates if templates else None,
            template_tags=tags if not templates else None,
            timeout=timeout
        )
    
    # ==================== VULNX: CVE Database ====================
    
    def search_cves(
        self,
        query: str = "",
        product: str | None = None,
        vendor: str | None = None,
        severity: list[str] | None = None,
        kev_only: bool = False,
        has_poc: bool = False,
        has_template: bool = False,
        limit: int = 50,
        timeout: int | None = None
    ) -> list[CVEResult]:
        """
        Search CVE database using vulnx.
        
        Args:
            query: Search query
            product: Filter by product name
            vendor: Filter by vendor name
            severity: Filter by severity levels
            kev_only: Only KEV (Known Exploited Vulnerabilities)
            has_poc: Only CVEs with proof of concept
            has_template: Only CVEs with nuclei templates
            limit: Maximum results
            timeout: Custom timeout
            
        Returns:
            List of CVE results
        """
        if not self.is_tool_available("vulnx"):
            return []
        
        cmd = ["vulnx", "search", "--json", "--silent"]
        
        if product:
            cmd.extend(["--product", product])
        if vendor:
            cmd.extend(["--vendor", vendor])
        if severity:
            cmd.extend(["--severity", ",".join(severity)])
        if kev_only:
            cmd.append("--kev")
        if has_poc:
            cmd.append("--poc")
        if has_template:
            cmd.append("--template")
        
        cmd.extend(["--limit", str(limit)])
        
        if query:
            cmd.append(query)
        
        result = self._run_command(cmd, "vulnx", timeout=timeout)
        
        cves = []
        for item in result.output:
            cves.append(CVEResult(
                cve_id=item.get("cve_id", item.get("id", "")),
                severity=item.get("severity", ""),
                cvss_score=item.get("cvss_score", item.get("cvss", {}).get("score", 0.0)),
                description=item.get("description", item.get("title", "")),
                affected_products=item.get("affected_products", []),
                is_kev=item.get("is_kev", False),
                is_poc=item.get("is_poc", item.get("has_poc", False)),
                is_template=item.get("is_template", item.get("has_nuclei_template", False)),
                references=item.get("references", [])
            ))
        
        return cves
    
    def get_cve_details(
        self,
        cve_id: str,
        timeout: int | None = None
    ) -> CVEResult | None:
        """
        Get detailed CVE information.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)
            timeout: Custom timeout
            
        Returns:
            CVE details or None if not found
        """
        if not self.is_tool_available("vulnx"):
            return None
        
        cmd = ["vulnx", "id", cve_id, "--json"]
        result = self._run_command(cmd, "vulnx", timeout=timeout)
        
        if result.output:
            item = result.output[0]
            return CVEResult(
                cve_id=item.get("cve_id", cve_id),
                severity=item.get("severity", ""),
                cvss_score=item.get("cvss_score", 0.0),
                description=item.get("description", ""),
                affected_products=item.get("affected_products", []),
                is_kev=item.get("is_kev", False),
                is_poc=item.get("is_poc", False),
                is_template=item.get("is_template", False),
                references=item.get("references", [])
            )
        return None
    
    # ==================== COMBINED WORKFLOWS ====================
    
    def full_recon(
        self,
        domain: str,
        include_ports: bool = True,
        include_http_probe: bool = True,
        include_crawl: bool = True,
        timeout: int | None = None
    ) -> dict[str, Any]:
        """
        Perform full reconnaissance on a domain.
        
        Pipeline: subfinder → naabu → httpx → katana
        
        Args:
            domain: Target domain
            include_ports: Run port scan
            include_http_probe: Run HTTP probing
            include_crawl: Run web crawling
            timeout: Custom timeout per step
            
        Returns:
            Dict with all reconnaissance data
        """
        results = {
            "domain": domain,
            "subdomains": [],
            "ports": [],
            "http_services": [],
            "crawled_urls": [],
            "stats": {}
        }
        
        # Step 1: Subdomain discovery
        if self.verbose:
            print(f"[*] Discovering subdomains for {domain}...")
        
        subdomains = self.discover_subdomains(domain, timeout=timeout)
        results["subdomains"] = subdomains
        results["stats"]["subdomains"] = len(subdomains)
        
        # Collect hosts for next steps
        hosts = [s.subdomain for s in subdomains if s.subdomain]
        if not hosts:
            hosts = [domain]
        
        # Step 2: Port scanning
        if include_ports and hosts:
            if self.verbose:
                print(f"[*] Scanning ports on {len(hosts)} hosts...")
            
            ports = self.scan_ports(hosts, ports="top-100", timeout=timeout)
            results["ports"] = ports
            results["stats"]["open_ports"] = len(ports)
        
        # Step 3: HTTP probing
        if include_http_probe and hosts:
            if self.verbose:
                print(f"[*] Probing HTTP services...")
            
            http_results = self.probe_http(hosts, timeout=timeout)
            results["http_services"] = http_results
            results["stats"]["http_services"] = len(http_results)
        
        # Step 4: Web crawling
        if include_crawl and results["http_services"]:
            if self.verbose:
                print(f"[*] Crawling web applications...")
            
            urls = [h.url for h in results["http_services"] if h.url]
            if urls:
                crawled = self.crawl(urls[:10], timeout=timeout)  # Limit to first 10
                results["crawled_urls"] = crawled
                results["stats"]["crawled_urls"] = len(crawled)
        
        return results
    
    def vuln_scan_pipeline(
        self,
        targets: list[str],
        severity: list[str] | None = None,
        tags: list[str] | None = None,
        crawl_first: bool = True,
        timeout: int | None = None
    ) -> dict[str, Any]:
        """
        Full vulnerability scanning pipeline.
        
        Pipeline: httpx → katana → nuclei
        
        Args:
            targets: Initial target URLs
            severity: Minimum severity to report
            tags: Template tags to use
            crawl_first: Crawl before scanning
            timeout: Custom timeout per step
            
        Returns:
            Dict with all vulnerability findings
        """
        results = {
            "targets": targets,
            "live_hosts": [],
            "crawled_urls": [],
            "vulnerabilities": [],
            "stats": {}
        }
        
        # Step 1: Probe live hosts
        if self.verbose:
            print(f"[*] Probing {len(targets)} targets...")
        
        http_results = self.probe_http(targets, timeout=timeout)
        results["live_hosts"] = http_results
        results["stats"]["live_hosts"] = len(http_results)
        
        live_urls = [h.url for h in http_results if h.url and h.status_code > 0]
        
        if not live_urls:
            return results
        
        # Step 2: Crawl (optional)
        if crawl_first:
            if self.verbose:
                print(f"[*] Crawling {len(live_urls)} live hosts...")
            
            crawled = self.crawl(live_urls, timeout=timeout)
            results["crawled_urls"] = crawled
            results["stats"]["crawled_urls"] = len(crawled)
            
            # Add crawled URLs to scan targets
            scan_targets = list(set(live_urls + [c.url for c in crawled if c.url]))
        else:
            scan_targets = live_urls
        
        # Step 3: Nuclei scan
        if self.verbose:
            print(f"[*] Scanning {len(scan_targets)} URLs with nuclei...")
        
        severity = severity or ["critical", "high", "medium"]
        vulns = self.scan_vulnerabilities(
            targets=scan_targets,
            template_tags=tags,
            severity=severity,
            timeout=timeout
        )
        
        results["vulnerabilities"] = vulns
        results["stats"]["vulnerabilities"] = len(vulns)
        results["stats"]["by_severity"] = {}
        
        for vuln in vulns:
            sev = vuln.severity.lower()
            results["stats"]["by_severity"][sev] = results["stats"]["by_severity"].get(sev, 0) + 1
        
        return results


# Convenience function for scanner integration
def get_pd_tools(
    timeout: int = 300,
    rate_limit: int = 150,
    threads: int = 25,
    verbose: bool = False,
    proxy: str | None = None
) -> ProjectDiscoveryTools:
    """Get configured ProjectDiscovery tools instance."""
    return ProjectDiscoveryTools(
        timeout=timeout,
        rate_limit=rate_limit,
        threads=threads,
        verbose=verbose,
        proxy=proxy
    )
