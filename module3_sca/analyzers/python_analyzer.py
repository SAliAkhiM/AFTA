import os
import re
from typing import List
from .base import BaseAnalyzer, DiscoveredPackage


class PythonAnalyzer(BaseAnalyzer):
    """
    Analyzes Python manifest files: requirements.txt, poetry.lock, Pipfile.lock.
    """

    SUPPORTED_FILES = {"requirements.txt", "poetry.lock", "pipfile.lock"}

    def can_analyze(self, filename: str) -> bool:
        base = os.path.basename(filename).lower()
        return base in self.SUPPORTED_FILES or base.endswith("requirements.txt")

    def analyze(self, filepath: str) -> List[DiscoveredPackage]:
        filename = os.path.basename(filepath).lower()
        if "requirements" in filename:
            return self._parse_requirements_txt(filepath)
        return []

    def _parse_requirements_txt(self, filepath: str) -> List[DiscoveredPackage]:
        packages: List[DiscoveredPackage] = []
        pattern = re.compile(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=|>|<)\s*([a-zA-Z0-9_\-\.]+)")

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#") or clean_line.startswith("-"):
                    continue

                match = pattern.match(clean_line)
                if match:
                    pkg_name = match.group(1).lower().strip()
                    pkg_version = match.group(2).strip()
                    packages.append(
                        DiscoveredPackage(
                            name=pkg_name,
                            version=pkg_version,
                            ecosystem="PyPI",
                            manifest_path=filepath,
                            line_number=idx
                        )
                    )
        return packages
