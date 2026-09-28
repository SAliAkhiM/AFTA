from abc import ABC, abstractmethod
from typing import List, Optional
from pydantic import BaseModel, Field


class DiscoveredPackage(BaseModel):
    name: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    ecosystem: str = Field(..., description="Ecosystem (e.g. PyPI, npm, Maven, Go)")
    manifest_path: str = Field(..., description="Path to the manifest file")
    line_number: Optional[int] = Field(None, description="Line number in manifest if available")
    purl: Optional[str] = Field(None, description="Package URL (purl specification)")

    def get_purl(self) -> str:
        if self.purl:
            return self.purl
        eco = self.ecosystem.lower()
        if eco == "pypi":
            return f"pkg:pypi/{self.name}@{self.version}"
        elif eco == "npm":
            return f"pkg:npm/{self.name}@{self.version}"
        elif eco == "maven":
            return f"pkg:maven/{self.name}@{self.version}"
        elif eco == "golang" or eco == "go":
            return f"pkg:golang/{self.name}@{self.version}"
        return f"pkg:generic/{self.name}@{self.version}"


class BaseAnalyzer(ABC):
    """
    Abstract base class for ecosystem manifest analyzers.
    """

    @abstractmethod
    def can_analyze(self, filename: str) -> bool:
        """Returns True if this analyzer handles the given manifest filename."""
        pass

    @abstractmethod
    def analyze(self, filepath: str) -> List[DiscoveredPackage]:
        """Parses the manifest and returns all discovered packages."""
        pass
