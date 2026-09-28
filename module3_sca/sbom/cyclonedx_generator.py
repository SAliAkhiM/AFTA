import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
from module3_sca.analyzers.base import DiscoveredPackage


class CycloneDXGenerator:
    """
    Generates CycloneDX v1.5 standard SBOM (JSON format) from discovered packages.
    """

    def __init__(self, project_name: str = "afta-scanned-project", project_version: str = "1.0.0"):
        self.project_name = project_name
        self.project_version = project_version

    def generate(self, packages: List[DiscoveredPackage]) -> Dict[str, Any]:
        """
        Builds a CycloneDX v1.5 compliant SBOM dictionary.
        """
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "AFTA Security Platform",
                        "name": "AFTA-SCA",
                        "version": "1.0.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": self.project_name,
                    "version": self.project_version
                }
            },
            "components": [
                {
                    "type": "library",
                    "name": pkg.name,
                    "version": pkg.version,
                    "purl": pkg.get_purl(),
                    "properties": [
                        {"name": "ecosystem", "value": pkg.ecosystem},
                        {"name": "manifest_path", "value": pkg.manifest_path}
                    ]
                }
                for pkg in packages
            ]
        }
        return bom
