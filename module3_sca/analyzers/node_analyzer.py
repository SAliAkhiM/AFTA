import json
import os
import re
from typing import List
from .base import BaseAnalyzer, DiscoveredPackage


class NodeAnalyzer(BaseAnalyzer):
    """
    Analyzes Node.js manifest files: package.json, package-lock.json.
    """

    SUPPORTED_FILES = {"package.json", "package-lock.json"}

    def can_analyze(self, filename: str) -> bool:
        base = os.path.basename(filename).lower()
        return base in self.SUPPORTED_FILES

    def analyze(self, filepath: str) -> List[DiscoveredPackage]:
        filename = os.path.basename(filepath).lower()
        if filename == "package.json":
            return self._parse_package_json(filepath)
        elif filename == "package-lock.json":
            return self._parse_package_lock_json(filepath)
        return []

    def _clean_version(self, version_str: str) -> str:
        # Strip ^, ~, >=, etc.
        return re.sub(r"^[\^~>=< ]+", "", version_str).strip()

    def _parse_package_json(self, filepath: str) -> List[DiscoveredPackage]:
        packages: List[DiscoveredPackage] = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})

            for name, ver in {**deps, **dev_deps}.items():
                clean_ver = self._clean_version(ver)
                if clean_ver:
                    packages.append(
                        DiscoveredPackage(
                            name=name,
                            version=clean_ver,
                            ecosystem="npm",
                            manifest_path=filepath
                        )
                    )
        except Exception:
            pass
        return packages

    def _parse_package_lock_json(self, filepath: str) -> List[DiscoveredPackage]:
        packages: List[DiscoveredPackage] = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Support package-lock v2 and v3 (packages dict)
            if "packages" in data and isinstance(data["packages"], dict):
                for pkg_path, info in data["packages"].items():
                    if not pkg_path or not isinstance(info, dict):
                        continue
                    name = info.get("name") or pkg_path.split("node_modules/")[-1]
                    version = info.get("version")
                    if name and version and not pkg_path == "":
                        packages.append(
                            DiscoveredPackage(
                                name=name,
                                version=version,
                                ecosystem="npm",
                                manifest_path=filepath
                            )
                        )
            # Fallback to v1 (dependencies dict)
            elif "dependencies" in data and isinstance(data["dependencies"], dict):
                for name, info in data["dependencies"].items():
                    if isinstance(info, dict) and "version" in info:
                        packages.append(
                            DiscoveredPackage(
                                name=name,
                                version=info["version"],
                                ecosystem="npm",
                                manifest_path=filepath
                            )
                        )
        except Exception:
            pass
        return packages
