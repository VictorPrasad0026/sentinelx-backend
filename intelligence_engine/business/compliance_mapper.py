"""
SentinelX Compliance Mapper

Maps findings to compliance frameworks:
GDPR, PCI-DSS, ISO 27001, NIST, HIPAA, SOC2
"""

from typing import Dict, Any, List


COMPLIANCE_MAP = {
    "Missing HSTS":                 ["PCI-DSS 6.5.10", "NIST SP 800-52"],
    "Missing Content Security":     ["OWASP ASVS 14.4", "ISO 27001 A.14"],
    "DMARC policy":                 ["NIST SP 800-177", "DMARC RFC 7489"],
    "Missing SPF":                  ["NIST SP 800-177", "PCI-DSS 12.3"],
    "DKIM":                         ["NIST SP 800-177"],
    "SSL certificate":              ["PCI-DSS 4.1", "HIPAA § 164.312(e)(2)(ii)"],
    "Weak TLS":                     ["PCI-DSS 6.5.4", "NIST SP 800-52 Rev2"],
    "database":                     ["PCI-DSS 6.4", "GDPR Article 32", "HIPAA § 164.312"],
    "docker":                       ["CIS Docker Benchmark", "NIST SP 800-190"],
    "kube":                         ["CIS Kubernetes Benchmark", "NIST SP 800-190"],
    "SMB":                          ["CIS Control 4.1"],
    "RDP":                          ["CIS Control 4.1", "NIST SP 800-46"],
    "Admin":                        ["ISO 27001 A.9.2", "PCI-DSS 7.1"],
}


class ComplianceMapper:

    def map_findings(self, findings: List[Dict]) -> List[Dict]:
        mapped = []
        for f in findings:
            issue = f.get("issue", "")
            frameworks = []
            for keyword, controls in COMPLIANCE_MAP.items():
                if keyword.lower() in issue.lower():
                    frameworks.extend(controls)
            if frameworks:
                mapped.append({
                    "finding": issue,
                    "severity": f.get("severity"),
                    "compliance_violations": list(set(frameworks))
                })
        return mapped

    def generate_compliance_report(self, findings: List[Dict]) -> Dict[str, List[str]]:
        report: Dict[str, List[str]] = {}
        for item in self.map_findings(findings):
            for ctrl in item["compliance_violations"]:
                framework = ctrl.split(" ")[0]
                report.setdefault(framework, []).append(item["finding"])
        return report
