import os
import re
from typing import List, Dict, Any, Optional
from common.models import (
    UnifiedScanReport,
    ScanMetadata,
    Finding,
    Location,
    FindingMetadata,
    Severity,
    ModuleType
)
from module3_sca.analyzers.base import BaseAnalyzer, DiscoveredPackage
from module3_sca.analyzers.python_analyzer import PythonAnalyzer
from module3_sca.analyzers.node_analyzer import NodeAnalyzer
from module3_sca.sbom.cyclonedx_generator import CycloneDXGenerator
from module3_sca.vulnerability.osv_client import OSVClient
from module3_sca.vulnerability.epss_client import EPSSClient
from module3_sca.vulnerability.risk_matrix import RiskMatrixCalculator


class SCAEngine:
    """
    Main orchestration engine for Module 3 (SCA):
    1. Scans project directory for manifest files.
    2. Extracts dependencies across ecosystems (PyPI, npm, etc.).
    3. Produces CycloneDX v1.5 SBOM.
    4. Queries vulnerability databases (OSV) and fetches EPSS metrics.
    5. Applies composite risk matrix scoring.
    6. Outputs Unified Data Contract compliant scan report.
    """

    def __init__(self, use_remote_apis: bool = True):
        self.analyzers: List[BaseAnalyzer] = [
            PythonAnalyzer(),
            NodeAnalyzer()
        ]
        self.sbom_generator = CycloneDXGenerator()
        self.use_remote_apis = use_remote_apis
        self.osv_client = OSVClient() if use_remote_apis else None
        self.epss_client = EPSSClient() if use_remote_apis else None

    def scan_path(self, target_path: str) -> Dict[str, Any]:
        """
        Scans a target directory or file and returns:
        {
            "report": UnifiedScanReport,
            "sbom": Dict[str, Any] (CycloneDX JSON)
        }
        """
        packages = self._discover_packages(target_path)
        sbom = self.sbom_generator.generate(packages)
        findings = self._audit_packages(packages, target_path)

        metadata = ScanMetadata(
            module_type=ModuleType.SCA,
            tool_name="AFTA-SCA-Engine",
            tool_version="1.0.0",
            target=os.path.abspath(target_path)
        )

        unified_report = UnifiedScanReport(
            scan_metadata=metadata,
            findings=findings
        )

        return {
            "report": unified_report,
            "sbom": sbom
        }

    def _discover_packages(self, target_path: str) -> List[DiscoveredPackage]:
        discovered: List[DiscoveredPackage] = []
        if os.path.isfile(target_path):
            filename = os.path.basename(target_path)
            for analyzer in self.analyzers:
                if analyzer.can_analyze(filename):
                    discovered.extend(analyzer.analyze(target_path))
            return discovered

        for root, _, files in os.walk(target_path):
            # Skip hidden or typical ignore folders
            if any(part.startswith(".") or part in {"node_modules", "venv", "__pycache__"} for part in root.split(os.sep)):
                continue
            for f in files:
                for analyzer in self.analyzers:
                    if analyzer.can_analyze(f):
                        full_path = os.path.join(root, f)
                        discovered.extend(analyzer.analyze(full_path))
        return discovered

    def _extract_cwe_id(self, vuln_data: Dict[str, Any]) -> Optional[int]:
        # Attempt to extract CWE from database_specific or references
        details = str(vuln_data.get("details", "")) + str(vuln_data.get("summary", ""))
        cwe_match = re.search(r"CWE-(\d+)", details, re.IGNORECASE)
        if cwe_match:
            return int(cwe_match.group(1))
        # Check database_specific
        db_spec = vuln_data.get("database_specific", {})
        if isinstance(db_spec, dict) and "cwe_ids" in db_spec:
            cwes = db_spec.get("cwe_ids", [])
            if cwes and isinstance(cwes, list):
                first = cwes[0]
                num_match = re.search(r"\d+", str(first))
                if num_match:
                    return int(num_match.group(0))
        return 1395  # Default CWE-1395: Dependency on Vulnerable Third-Party Component

    def _extract_cve_id(self, vuln_data: Dict[str, Any]) -> Optional[str]:
        vid = vuln_data.get("id", "")
        if vid.upper().startswith("CVE-"):
            return vid
        for alias in vuln_data.get("aliases", []):
            if alias.upper().startswith("CVE-"):
                return alias
        return vid if vid else None

    def _extract_cvss_score(self, vuln_data: Dict[str, Any]) -> float:
        # Check severity field in OSV
        for sev in vuln_data.get("severity", []):
            score_str = sev.get("score")
            # If CVSS vector, we can estimate or fallback
            if score_str and isinstance(score_str, (int, float)):
                return float(score_str)
        # Fallback heuristic based on database_specific severity if any
        db_spec = vuln_data.get("database_specific", {})
        if isinstance(db_spec, dict):
            sev_rating = str(db_spec.get("severity", "")).upper()
            if "CRITICAL" in sev_rating:
                return 9.5
            elif "HIGH" in sev_rating:
                return 7.8
            elif "MODERATE" in sev_rating or "MEDIUM" in sev_rating:
                return 5.5
            elif "LOW" in sev_rating:
                return 3.0
        return 7.0  # Conservative default for known unpatched vulnerability

    def _audit_packages(self, packages: List[DiscoveredPackage], target_path: str) -> List[Finding]:
        findings: List[Finding] = []

        if not self.use_remote_apis or not self.osv_client:
            return findings

        for pkg in packages:
            vulns = self.osv_client.query_package(pkg.name, pkg.version, pkg.ecosystem)
            for v in vulns:
                cve_id = self._extract_cve_id(v)
                cwe_id = self._extract_cwe_id(v)
                cvss_score = self._extract_cvss_score(v)

                # Fetch EPSS if CVE is present
                epss_score = 0.01
                epss_percentile = 0.10
                if cve_id and self.epss_client:
                    epss_data = self.epss_client.get_score(cve_id)
                    if epss_data:
                        epss_score = epss_data.get("epss", 0.01)
                        epss_percentile = epss_data.get("percentile", 0.10)

                # Calculate composite risk
                risk_info = RiskMatrixCalculator.calculate_priority(cvss_score, epss_score)
                severity = risk_info["adjusted_severity"]

                # Extract fix recommendation
                fix_rec = "Upgrade package to a non-vulnerable version."
                for affected in v.get("affected", []):
                    ranges = affected.get("ranges", [])
                    for r in ranges:
                        for event in r.get("events", []):
                            if "fixed" in event:
                                fix_rec = f"Upgrade '{pkg.name}' to version >= {event['fixed']}"
                                break

                # Generate fingerprint
                rule_id = cve_id or v.get("id", "SCA-VULN")
                fingerprint = Finding.create_fingerprint(
                    rule_id=rule_id,
                    path_or_url=pkg.manifest_path,
                    line_or_param=str(pkg.line_number or pkg.name)
                )

                finding = Finding(
                    fingerprint=fingerprint,
                    rule_id=rule_id,
                    title=f"Vulnerable Dependency: {pkg.name}@{pkg.version} ({rule_id})",
                    description=v.get("summary") or v.get("details", "Known vulnerability in dependency."),
                    severity=severity,
                    cwe_id=cwe_id,
                    cve_id=cve_id,
                    location=Location(
                        path_or_url=pkg.manifest_path,
                        start_line=pkg.line_number,
                        parameter=pkg.name
                    ),
                    metadata=FindingMetadata(
                        cvss_score=cvss_score,
                        epss_score=epss_score,
                        epss_percentile=epss_percentile,
                        fix_recommendation=fix_rec,
                        package_name=pkg.name,
                        installed_version=pkg.version
                    )
                )
                findings.append(finding)

        return findings
