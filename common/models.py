import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class ModuleType(str, Enum):
    SAST = "SAST"
    DAST = "DAST"
    SCA = "SCA"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Location(BaseModel):
    path_or_url: str = Field(..., description="File path, URL, or package identifier")
    start_line: Optional[int] = Field(None, description="Line number if applicable")
    parameter: Optional[str] = Field(None, description="Vulnerable parameter if applicable")


class FindingMetadata(BaseModel):
    cvss_score: Optional[float] = Field(None, description="CVSS v3.x base score (0.0 to 10.0)")
    epss_score: Optional[float] = Field(None, description="EPSS probability score (0.0 to 1.0)")
    epss_percentile: Optional[float] = Field(None, description="EPSS percentile score (0.0 to 1.0)")
    fix_recommendation: Optional[str] = Field(None, description="Remediation guidance or upgrade advice")
    package_name: Optional[str] = Field(None, description="Affected package name for SCA")
    installed_version: Optional[str] = Field(None, description="Installed package version")
    fixed_version: Optional[str] = Field(None, description="Fixed package version if available")


class Finding(BaseModel):
    fingerprint: str = Field(..., description="SHA256 fingerprint for deduplication")
    rule_id: str = Field(..., description="Rule ID, vulnerability ID or check name")
    title: str = Field(..., description="Short title of the finding")
    description: str = Field(..., description="Detailed description of the vulnerability")
    severity: Severity = Field(..., description="Severity level")
    cwe_id: Optional[int] = Field(None, description="CWE identifier (e.g. 89)")
    cve_id: Optional[str] = Field(None, description="CVE identifier (e.g. CVE-2023-12345)")
    location: Location = Field(..., description="Location of the finding")
    metadata: FindingMetadata = Field(default_factory=FindingMetadata)

    @classmethod
    def create_fingerprint(cls, rule_id: str, path_or_url: str, line_or_param: Optional[str] = "") -> str:
        """
        Generates deterministic SHA256 fingerprint:
        SHA256(rule_id + file_or_endpoint + line_or_param)
        """
        raw_key = f"{rule_id}:{path_or_url}:{line_or_param or ''}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


class ScanMetadata(BaseModel):
    module_type: ModuleType = Field(..., description="Source module type (SAST, DAST, or SCA)")
    tool_name: str = Field(..., description="Name of the underlying tool or engine")
    tool_version: str = Field(default="1.0.0", description="Version of the scanning tool")
    target: str = Field(..., description="Scan target (repo path, manifest path, or URL)")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 timestamp"
    )


class UnifiedScanReport(BaseModel):
    """
    Unified Data Contract for all AFTA scanner modules (SAST, DAST, SCA).
    """
    scan_metadata: ScanMetadata
    findings: List[Finding] = Field(default_factory=list)
