"""
Reporting & Integration Module.

Generates professional security reports and integrates with external tools:
- HTML/PDF report generation
- CVSS scoring
- Nuclei template generation
- Burp Suite integration
- Platform exports (HackerOne, Bugcrowd)

For security research only - requires proper authorization.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from string import Template
import html


@dataclass
class CVSSVector:
    """CVSS v3.1 scoring vector."""
    attack_vector: str = "N"  # N/A/L/P
    attack_complexity: str = "L"  # L/H
    privileges_required: str = "N"  # N/L/H
    user_interaction: str = "N"  # N/R
    scope: str = "U"  # U/C
    confidentiality: str = "H"  # N/L/H
    integrity: str = "H"  # N/L/H
    availability: str = "H"  # N/L/H
    
    @property
    def vector_string(self) -> str:
        """Generate CVSS vector string."""
        return f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/PR:{self.privileges_required}/UI:{self.user_interaction}/S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/A:{self.availability}"
    
    @property
    def base_score(self) -> float:
        """Calculate CVSS base score."""
        # Impact values
        impact_values = {
            "N": 0, "L": 0.22, "H": 0.56
        }
        
        # ISS = 1 - [(1 - C) × (1 - I) × (1 - A)]
        iss = 1 - (
            (1 - impact_values.get(self.confidentiality, 0)) *
            (1 - impact_values.get(self.integrity, 0)) *
            (1 - impact_values.get(self.availability, 0))
        )
        
        # Impact calculation
        if self.scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        
        # Exploitability values
        av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_values = {"L": 0.77, "H": 0.44}
        pr_values = {
            "U": {"N": 0.85, "L": 0.62, "H": 0.27},
            "C": {"N": 0.85, "L": 0.68, "H": 0.50}
        }
        ui_values = {"N": 0.85, "R": 0.62}
        
        exploitability = 8.22 * (
            av_values.get(self.attack_vector, 0.85) *
            ac_values.get(self.attack_complexity, 0.77) *
            pr_values.get(self.scope, {}).get(self.privileges_required, 0.85) *
            ui_values.get(self.user_interaction, 0.85)
        )
        
        # Base score
        if impact <= 0:
            return 0.0
        
        if self.scope == "U":
            base = min(impact + exploitability, 10)
        else:
            base = min(1.08 * (impact + exploitability), 10)
        
        # Round up to 1 decimal
        return round(base * 10) / 10
    
    @property
    def severity(self) -> str:
        """Get severity rating from score."""
        score = self.base_score
        if score == 0:
            return "None"
        elif score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        else:
            return "Critical"


class CVSSCalculator:
    """
    CVSS v3.1 calculator with preset vectors for common vulnerabilities.
    """
    
    # Preset vectors for common vulnerability types
    PRESETS = {
        "sqli_auth_bypass": CVSSVector(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="U", confidentiality="H", integrity="H", availability="N"
        ),
        "sqli_data_leak": CVSSVector(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="U", confidentiality="H", integrity="N", availability="N"
        ),
        "xss_stored": CVSSVector(
            attack_vector="N", attack_complexity="L",
            privileges_required="L", user_interaction="R",
            scope="C", confidentiality="L", integrity="L", availability="N"
        ),
        "xss_reflected": CVSSVector(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="R",
            scope="C", confidentiality="L", integrity="L", availability="N"
        ),
        "rce_unauth": CVSSVector(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="C", confidentiality="H", integrity="H", availability="H"
        ),
        "rce_auth": CVSSVector(
            attack_vector="N", attack_complexity="L",
            privileges_required="L", user_interaction="N",
            scope="C", confidentiality="H", integrity="H", availability="H"
        ),
        "ssrf_internal": CVSSVector(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="C", confidentiality="H", integrity="L", availability="N"
        ),
        "lfi_file_read": CVSSVector(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="U", confidentiality="H", integrity="N", availability="N"
        ),
        "xxe_file_read": CVSSVector(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="U", confidentiality="H", integrity="N", availability="N"
        ),
        "auth_bypass": CVSSVector(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="U", confidentiality="H", integrity="H", availability="N"
        ),
        "idor": CVSSVector(
            attack_vector="N", attack_complexity="L",
            privileges_required="L", user_interaction="N",
            scope="U", confidentiality="H", integrity="N", availability="N"
        ),
        "ssti_rce": CVSSVector(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="U", confidentiality="H", integrity="H", availability="H"
        ),
    }
    
    @classmethod
    def get_vector(cls, vuln_type: str) -> CVSSVector:
        """Get CVSS vector for vulnerability type."""
        # Normalize vuln type
        vuln_lower = vuln_type.lower().replace(" ", "_").replace("-", "_")
        
        # Direct match
        if vuln_lower in cls.PRESETS:
            return cls.PRESETS[vuln_lower]
        
        # Pattern matching
        if "sql" in vuln_lower:
            if "auth" in vuln_lower or "bypass" in vuln_lower:
                return cls.PRESETS["sqli_auth_bypass"]
            return cls.PRESETS["sqli_data_leak"]
        
        if "xss" in vuln_lower:
            if "stored" in vuln_lower:
                return cls.PRESETS["xss_stored"]
            return cls.PRESETS["xss_reflected"]
        
        if "rce" in vuln_lower or "command" in vuln_lower:
            if "unauth" in vuln_lower:
                return cls.PRESETS["rce_unauth"]
            return cls.PRESETS["rce_auth"]
        
        if "ssrf" in vuln_lower:
            return cls.PRESETS["ssrf_internal"]
        
        if "lfi" in vuln_lower or "file" in vuln_lower:
            return cls.PRESETS["lfi_file_read"]
        
        if "xxe" in vuln_lower:
            return cls.PRESETS["xxe_file_read"]
        
        if "auth" in vuln_lower or "bypass" in vuln_lower:
            return cls.PRESETS["auth_bypass"]
        
        if "idor" in vuln_lower:
            return cls.PRESETS["idor"]
        
        if "ssti" in vuln_lower or "template" in vuln_lower:
            return cls.PRESETS["ssti_rce"]
        
        # Default medium severity
        return CVSSVector()
    
    @classmethod
    def calculate(cls, vuln_type: str) -> dict:
        """Calculate CVSS score for vulnerability type."""
        vector = cls.get_vector(vuln_type)
        return {
            "vector_string": vector.vector_string,
            "base_score": vector.base_score,
            "severity": vector.severity
        }


class NucleiTemplateGenerator:
    """
    Generates Nuclei templates from discovered vulnerabilities.
    """
    
    TEMPLATE_HEADER = '''id: {template_id}

info:
  name: {name}
  author: attack-surface-framework
  severity: {severity}
  description: {description}
  tags: {tags}
  reference:
    - {reference}

'''
    
    HTTP_TEMPLATE = '''http:
  - raw:
      - |
        {method} {path} HTTP/1.1
        Host: {{{{Hostname}}}}
        {headers}
        
        {body}

    matchers-condition: and
    matchers:
      - type: word
        words:
{matchers}
        condition: or

      - type: status
        status:
          - {status}
'''
    
    @classmethod
    def generate(
        cls,
        vuln_type: str,
        target_url: str,
        payload: str,
        evidence: str,
        method: str = "POST",
        headers: dict = None,
        body: str = None,
        match_patterns: list[str] = None
    ) -> str:
        """Generate Nuclei template for vulnerability."""
        from urllib.parse import urlparse
        
        parsed = urlparse(target_url)
        path = parsed.path or "/"
        
        # Generate template ID
        template_id = f"asf-{vuln_type.lower().replace(' ', '-')}-{hashlib.md5(target_url.encode()).hexdigest()[:8]}"
        
        # Severity from CVSS
        cvss = CVSSCalculator.calculate(vuln_type)
        severity = cvss["severity"].lower()
        
        # Format headers
        headers_str = ""
        if headers:
            headers_str = "\n        ".join(f"{k}: {v}" for k, v in headers.items())
        
        # Format body
        body_str = body or payload
        
        # Format matchers
        patterns = match_patterns or [evidence[:50] if evidence else "error"]
        matchers_str = "\n".join(f'          - "{p}"' for p in patterns)
        
        # Build template
        template = cls.TEMPLATE_HEADER.format(
            template_id=template_id,
            name=f"{vuln_type} - {parsed.netloc}",
            severity=severity,
            description=f"Detected {vuln_type} vulnerability",
            tags=f"{vuln_type.lower().replace(' ', ',')},asf",
            reference=target_url
        )
        
        template += cls.HTTP_TEMPLATE.format(
            method=method.upper(),
            path=path,
            headers=headers_str,
            body=body_str,
            matchers=matchers_str,
            status="200"
        )
        
        return template
    
    @classmethod
    def save_template(cls, template: str, output_dir: Path, name: str) -> Path:
        """Save template to file."""
        output_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{name.lower().replace(' ', '-')}.yaml"
        filepath = output_dir / filename
        filepath.write_text(template)
        return filepath


class BurpSuiteIntegration:
    """
    Burp Suite integration for importing/exporting findings.
    """
    
    @staticmethod
    def export_to_burp_xml(findings: list[dict]) -> str:
        """Export findings to Burp Suite XML format."""
        root = ET.Element("issues")
        root.set("burpVersion", "2023.1")
        root.set("exportTime", datetime.now().isoformat())
        
        for finding in findings:
            issue = ET.SubElement(root, "issue")
            
            ET.SubElement(issue, "serialNumber").text = str(finding.get("id", ""))
            ET.SubElement(issue, "type").text = str(finding.get("type_id", 0))
            ET.SubElement(issue, "name").text = finding.get("vuln_type", "Unknown")
            ET.SubElement(issue, "host").text = finding.get("host", "")
            ET.SubElement(issue, "path").text = finding.get("path", "/")
            
            # Severity mapping
            severity_map = {"critical": "High", "high": "High", "medium": "Medium", "low": "Low"}
            severity = severity_map.get(finding.get("severity", "").lower(), "Information")
            ET.SubElement(issue, "severity").text = severity
            
            ET.SubElement(issue, "confidence").text = "Certain" if finding.get("confidence", 0) > 0.8 else "Tentative"
            
            # Issue detail
            detail = ET.SubElement(issue, "issueDetail")
            detail.text = f"""
                <![CDATA[
                Payload: {html.escape(finding.get('payload', ''))}
                Evidence: {html.escape(finding.get('evidence', ''))}
                ]]>
            """
            
            # Request/Response
            if finding.get("request"):
                req = ET.SubElement(issue, "requestresponse")
                ET.SubElement(req, "request").text = base64.b64encode(
                    finding["request"].encode()
                ).decode()
                if finding.get("response"):
                    ET.SubElement(req, "response").text = base64.b64encode(
                        finding["response"].encode()
                    ).decode()
        
        return ET.tostring(root, encoding="unicode", xml_declaration=True)
    
    @staticmethod
    def import_from_burp_xml(xml_content: str) -> list[dict]:
        """Import findings from Burp Suite XML."""
        findings = []
        root = ET.fromstring(xml_content)
        
        for issue in root.findall(".//issue"):
            finding = {
                "id": issue.findtext("serialNumber", ""),
                "vuln_type": issue.findtext("name", ""),
                "host": issue.findtext("host", ""),
                "path": issue.findtext("path", ""),
                "severity": issue.findtext("severity", "").lower(),
                "confidence": 0.9 if issue.findtext("confidence") == "Certain" else 0.6,
                "detail": issue.findtext("issueDetail", "")
            }
            
            # Decode request/response
            req_resp = issue.find("requestresponse")
            if req_resp is not None:
                req = req_resp.findtext("request")
                if req:
                    finding["request"] = base64.b64decode(req).decode("utf-8", errors="replace")
                resp = req_resp.findtext("response")
                if resp:
                    finding["response"] = base64.b64decode(resp).decode("utf-8", errors="replace")
            
            findings.append(finding)
        
        return findings


class HackerOneExporter:
    """
    Export findings to HackerOne report format.
    """
    
    REPORT_TEMPLATE = '''## Summary

{summary}

## Vulnerability Type

{vuln_type}

## Severity

**CVSS Score:** {cvss_score} ({severity})
**Vector:** `{cvss_vector}`

## Steps to Reproduce

{steps}

## Impact

{impact}

## Proof of Concept

```
{payload}
```

## Evidence

{evidence}

## Remediation

{remediation}

---
*Generated by Attack Surface Framework*
'''
    
    @classmethod
    def generate_report(
        cls,
        vuln_type: str,
        target_url: str,
        payload: str,
        evidence: str,
        steps: list[str] = None,
        impact: str = None
    ) -> str:
        """Generate HackerOne-style report."""
        # Calculate CVSS
        cvss = CVSSCalculator.calculate(vuln_type)
        
        # Default steps
        if not steps:
            steps = [
                f"1. Navigate to {target_url}",
                f"2. Submit the following payload: `{payload[:100]}`",
                "3. Observe the vulnerability behavior in response"
            ]
        
        # Default impact
        if not impact:
            impact_map = {
                "Critical": "This vulnerability allows complete system compromise, including unauthorized access to sensitive data, code execution, and potential lateral movement.",
                "High": "This vulnerability can lead to significant data exposure or unauthorized access to protected resources.",
                "Medium": "This vulnerability may allow limited access to sensitive information or enable further attacks.",
                "Low": "This vulnerability has limited impact but may be chained with other issues."
            }
            impact = impact_map.get(cvss["severity"], "Impact assessment required.")
        
        # Remediation suggestions
        remediation_map = {
            "sqli": "Use parameterized queries and prepared statements. Implement input validation and output encoding.",
            "xss": "Implement proper output encoding. Use Content-Security-Policy headers. Validate and sanitize user input.",
            "rce": "Avoid executing user-controlled input. Use allowlists for commands. Implement proper input validation.",
            "ssrf": "Validate and sanitize URLs. Use allowlists for permitted domains. Disable unnecessary URL schemes.",
            "lfi": "Validate file paths against an allowlist. Avoid using user input in file operations.",
            "xxe": "Disable external entity processing. Use safe XML parsers with DTD disabled.",
            "auth": "Implement proper authentication controls. Use secure session management.",
        }
        
        remediation = "Unknown vulnerability type - manual assessment required."
        for key, value in remediation_map.items():
            if key in vuln_type.lower():
                remediation = value
                break
        
        return cls.REPORT_TEMPLATE.format(
            summary=f"A {cvss['severity'].lower()} severity {vuln_type} vulnerability was discovered at {target_url}.",
            vuln_type=vuln_type,
            cvss_score=cvss["base_score"],
            severity=cvss["severity"],
            cvss_vector=cvss["vector_string"],
            steps="\n".join(steps),
            impact=impact,
            payload=payload,
            evidence=evidence[:500] if evidence else "See attached screenshots",
            remediation=remediation
        )


class BugcrowdExporter:
    """
    Export findings to Bugcrowd report format.
    """
    
    @classmethod
    def generate_report(
        cls,
        vuln_type: str,
        target_url: str,
        payload: str,
        evidence: str
    ) -> dict:
        """Generate Bugcrowd-compatible report data."""
        cvss = CVSSCalculator.calculate(vuln_type)
        
        # Map severity to Bugcrowd priority
        priority_map = {
            "Critical": "P1",
            "High": "P2",
            "Medium": "P3",
            "Low": "P4",
            "None": "P5"
        }
        
        return {
            "title": f"{vuln_type} at {target_url}",
            "priority": priority_map.get(cvss["severity"], "P3"),
            "vrt": cls._map_to_vrt(vuln_type),
            "target": target_url,
            "description": f"A {vuln_type} vulnerability was discovered.",
            "proof_of_concept": payload,
            "impact": f"CVSS {cvss['base_score']} - {cvss['severity']}",
            "extra_info": evidence,
            "cvss_vector": cvss["vector_string"]
        }
    
    @staticmethod
    def _map_to_vrt(vuln_type: str) -> str:
        """Map vulnerability type to Bugcrowd VRT category."""
        vrt_map = {
            "sqli": "server_side_injection.sql_injection",
            "xss": "cross_site_scripting_xss",
            "rce": "server_side_injection.remote_code_execution_rce",
            "ssrf": "server_side_request_forgery_ssrf",
            "lfi": "server_side_injection.file_inclusion_local",
            "xxe": "server_side_injection.xml_external_entity_injection_xxe",
            "auth": "broken_authentication_and_session_management",
            "idor": "insecure_direct_object_reference_idor",
            "ssti": "server_side_injection.server_side_template_injection",
        }
        
        vuln_lower = vuln_type.lower()
        for key, value in vrt_map.items():
            if key in vuln_lower:
                return value
        
        return "other"


class HTMLReportGenerator:
    """
    Generates professional HTML security reports.
    """
    
    HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - ${target}</title>
    <style>
        :root {
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --info: #17a2b8;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        
        .header h1 { font-size: 2.5rem; margin-bottom: 10px; }
        .header .meta { opacity: 0.8; }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .card.critical { border-left: 4px solid var(--critical); }
        .card.high { border-left: 4px solid var(--high); }
        .card.medium { border-left: 4px solid var(--medium); }
        .card.low { border-left: 4px solid var(--low); }
        
        .card h3 { font-size: 2rem; margin-bottom: 5px; }
        .card p { color: #666; }
        
        .findings { margin-bottom: 30px; }
        
        .finding {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .finding h3 { font-size: 1.3rem; }
        
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: bold;
            color: white;
        }
        
        .severity-critical { background: var(--critical); }
        .severity-high { background: var(--high); }
        .severity-medium { background: var(--medium); color: #333; }
        .severity-low { background: var(--low); }
        
        .finding-details { margin-top: 15px; }
        .finding-details dt { font-weight: bold; margin-top: 10px; }
        .finding-details dd { margin-left: 0; color: #555; }
        
        .code-block {
            background: #1a1a2e;
            color: #0f0;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            margin: 10px 0;
        }
        
        .cvss-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: #666;
        }
        
        @media print {
            body { background: white; }
            .header { background: #333; }
            .finding { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Assessment Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> ${target}</p>
                <p><strong>Date:</strong> ${date}</p>
                <p><strong>Generated by:</strong> Attack Surface Framework v${version}</p>
            </div>
        </div>
        
        <div class="summary-cards">
            <div class="card critical">
                <h3>${critical_count}</h3>
                <p>Critical</p>
            </div>
            <div class="card high">
                <h3>${high_count}</h3>
                <p>High</p>
            </div>
            <div class="card medium">
                <h3>${medium_count}</h3>
                <p>Medium</p>
            </div>
            <div class="card low">
                <h3>${low_count}</h3>
                <p>Low</p>
            </div>
        </div>
        
        <h2 style="margin-bottom: 20px;">Findings</h2>
        
        <div class="findings">
            ${findings_html}
        </div>
        
        <div class="footer">
            <p>This report was automatically generated by Attack Surface Framework.</p>
            <p>For authorized security research only.</p>
        </div>
    </div>
</body>
</html>
'''
    
    FINDING_TEMPLATE = '''
        <div class="finding">
            <div class="finding-header">
                <h3>${vuln_type}</h3>
                <span class="severity-badge severity-${severity_lower}">${severity}</span>
            </div>
            
            <dl class="finding-details">
                <dt>Target URL</dt>
                <dd><code>${target_url}</code></dd>
                
                <dt>Payload</dt>
                <dd><div class="code-block">${payload}</div></dd>
                
                <dt>Evidence</dt>
                <dd>${evidence}</dd>
                
                <dt>Confidence</dt>
                <dd>${confidence}%</dd>
            </dl>
            
            <div class="cvss-info">
                <strong>CVSS v3.1:</strong> ${cvss_score} (${severity})<br>
                <code>${cvss_vector}</code>
            </div>
        </div>
    '''
    
    @classmethod
    def generate(
        cls,
        target: str,
        findings: list[dict],
        version: str = "0.8.0"
    ) -> str:
        """Generate HTML report from findings."""
        # Count severities
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        # Generate findings HTML
        findings_html = ""
        for finding in findings:
            vuln_type = finding.get("vuln_type", "Unknown")
            cvss = CVSSCalculator.calculate(vuln_type)
            severity = cvss["severity"]
            severity_counts[severity.lower()] = severity_counts.get(severity.lower(), 0) + 1
            
            finding_html = Template(cls.FINDING_TEMPLATE).safe_substitute(
                vuln_type=html.escape(vuln_type),
                severity=severity,
                severity_lower=severity.lower(),
                target_url=html.escape(finding.get("target_url", "")),
                payload=html.escape(finding.get("payload", "")[:500]),
                evidence=html.escape(finding.get("evidence", "")[:300]),
                confidence=int(finding.get("confidence", 0) * 100),
                cvss_score=cvss["base_score"],
                cvss_vector=cvss["vector_string"]
            )
            findings_html += finding_html
        
        # Generate full report
        report = Template(cls.HTML_TEMPLATE).safe_substitute(
            target=html.escape(target),
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            version=version,
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            findings_html=findings_html
        )
        
        return report
    
    @classmethod
    def save_report(cls, report: str, output_path: Path) -> Path:
        """Save HTML report to file."""
        output_path.write_text(report, encoding="utf-8")
        return output_path


class ReportGenerator:
    """
    Unified report generator supporting multiple formats.
    """
    
    def __init__(self, target: str, findings: list[dict]):
        self.target = target
        self.findings = findings
    
    def generate_html(self, output_path: Path = None) -> str:
        """Generate HTML report."""
        report = HTMLReportGenerator.generate(self.target, self.findings)
        if output_path:
            HTMLReportGenerator.save_report(report, output_path)
        return report
    
    def generate_nuclei_templates(self, output_dir: Path) -> list[Path]:
        """Generate Nuclei templates for all findings."""
        paths = []
        for finding in self.findings:
            template = NucleiTemplateGenerator.generate(
                vuln_type=finding.get("vuln_type", "unknown"),
                target_url=finding.get("target_url", ""),
                payload=finding.get("payload", ""),
                evidence=finding.get("evidence", "")
            )
            path = NucleiTemplateGenerator.save_template(
                template,
                output_dir,
                f"{finding.get('vuln_type', 'unknown')}_{len(paths)}"
            )
            paths.append(path)
        return paths
    
    def generate_burp_xml(self, output_path: Path = None) -> str:
        """Generate Burp Suite XML."""
        xml = BurpSuiteIntegration.export_to_burp_xml(self.findings)
        if output_path:
            output_path.write_text(xml)
        return xml
    
    def generate_hackerone(self, output_dir: Path = None) -> list[str]:
        """Generate HackerOne reports for all findings."""
        reports = []
        for i, finding in enumerate(self.findings):
            report = HackerOneExporter.generate_report(
                vuln_type=finding.get("vuln_type", ""),
                target_url=finding.get("target_url", ""),
                payload=finding.get("payload", ""),
                evidence=finding.get("evidence", "")
            )
            reports.append(report)
            
            if output_dir:
                output_dir.mkdir(parents=True, exist_ok=True)
                (output_dir / f"hackerone_report_{i+1}.md").write_text(report)
        
        return reports
    
    def generate_bugcrowd(self) -> list[dict]:
        """Generate Bugcrowd report data."""
        return [
            BugcrowdExporter.generate_report(
                vuln_type=f.get("vuln_type", ""),
                target_url=f.get("target_url", ""),
                payload=f.get("payload", ""),
                evidence=f.get("evidence", "")
            )
            for f in self.findings
        ]
    
    def generate_json(self, output_path: Path = None) -> str:
        """Generate JSON report."""
        report_data = {
            "target": self.target,
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings": []
        }
        
        for finding in self.findings:
            cvss = CVSSCalculator.calculate(finding.get("vuln_type", ""))
            report_data["findings"].append({
                **finding,
                "cvss": cvss
            })
        
        json_str = json.dumps(report_data, indent=2, default=str)
        
        if output_path:
            output_path.write_text(json_str)
        
        return json_str


# Export classes
__all__ = [
    "CVSSVector",
    "CVSSCalculator",
    "NucleiTemplateGenerator",
    "BurpSuiteIntegration",
    "HackerOneExporter",
    "BugcrowdExporter",
    "HTMLReportGenerator",
    "ReportGenerator",
]
