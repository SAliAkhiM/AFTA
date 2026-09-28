import os
import pytest
from module3_sca.analyzers.python_analyzer import PythonAnalyzer
from module3_sca.analyzers.node_analyzer import NodeAnalyzer
from module3_sca.sbom.cyclonedx_generator import CycloneDXGenerator
from module3_sca.vulnerability.risk_matrix import RiskMatrixCalculator
from common.models import Severity


def test_python_analyzer():
    analyzer = PythonAnalyzer()
    req_path = os.path.join(os.path.dirname(__file__), "..", "samples", "vulnerable_app", "requirements.txt")
    assert os.path.exists(req_path)

    packages = analyzer.analyze(req_path)
    assert len(packages) >= 3
    names = [p.name for p in packages]
    assert "flask" in names
    assert "requests" in names


def test_node_analyzer():
    analyzer = NodeAnalyzer()
    pkg_path = os.path.join(os.path.dirname(__file__), "..", "samples", "vulnerable_app", "package.json")
    assert os.path.exists(pkg_path)

    packages = analyzer.analyze(pkg_path)
    assert len(packages) >= 2
    names = [p.name for p in packages]
    assert "lodash" in names


def test_cyclonedx_generation():
    analyzer = PythonAnalyzer()
    req_path = os.path.join(os.path.dirname(__file__), "..", "samples", "vulnerable_app", "requirements.txt")
    packages = analyzer.analyze(req_path)

    generator = CycloneDXGenerator(project_name="test-project")
    bom = generator.generate(packages)

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert len(bom["components"]) == len(packages)
    assert bom["components"][0]["purl"].startswith("pkg:pypi/")


def test_risk_matrix():
    # Critical CVSS + High EPSS -> Urgent Critical
    res1 = RiskMatrixCalculator.calculate_priority(cvss_score=9.8, epss_score=0.25)
    assert res1["adjusted_severity"] == Severity.CRITICAL
    assert res1["priority_code"] == "P1_URGENT_CRITICAL"

    # Moderate CVSS + High EPSS -> Elevated High
    res2 = RiskMatrixCalculator.calculate_priority(cvss_score=5.0, epss_score=0.15)
    assert res2["adjusted_severity"] == Severity.HIGH
