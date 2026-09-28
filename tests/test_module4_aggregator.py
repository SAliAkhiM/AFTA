import os
import pytest
from module4_aggregator.ingestion.parser import ScanParser
from module4_aggregator.correlation.correlator import Correlator
from module4_aggregator.afta_compliance.evaluator import AFTAEvaluator
from module4_aggregator.reporting.report_generator import ReportGenerator


def test_parser_and_correlation():
    samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")
    sast_file = os.path.join(samples_dir, "sast_sample.json")
    dast_file = os.path.join(samples_dir, "dast_sample.json")

    sast_report = ScanParser.parse_file(sast_file)
    dast_report = ScanParser.parse_file(dast_file)

    assert len(sast_report.findings) == 2
    assert len(dast_report.findings) == 2

    # Correlation
    correlated = Correlator.correlate(sast_report.findings, dast_report.findings, [])
    assert len(correlated) > 0

    # Cross verification check: SQL Injection should match between SAST and DAST
    cross_verified = [c for c in correlated if c.is_cross_verified]
    assert len(cross_verified) == 1
    assert cross_verified[0].finding.cwe_id == 89


def test_afta_compliance_evaluator():
    samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")
    sast_file = os.path.join(samples_dir, "sast_sample.json")
    sast_report = ScanParser.parse_file(sast_file)

    evaluator = AFTAEvaluator()
    result = evaluator.evaluate(sast_report.findings)

    assert "compliance_score" in result
    assert "verdict" in result
    # We have a CRITICAL finding (hardcoded secret), so verdict should be FAILED
    assert result["verdict_code"] == "FAILED"
    assert result["severity_summary"]["CRITICAL"] >= 1


def test_report_generation(tmp_path):
    samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")
    sast_file = os.path.join(samples_dir, "sast_sample.json")
    dast_file = os.path.join(samples_dir, "dast_sample.json")

    sast_report = ScanParser.parse_file(sast_file)
    dast_report = ScanParser.parse_file(dast_file)

    correlated = Correlator.correlate(sast_report.findings, dast_report.findings, [])
    evaluator = AFTAEvaluator()
    compliance_res = evaluator.evaluate([c.finding for c in correlated])

    out_file = os.path.join(tmp_path, "test_report.html")
    generator = ReportGenerator()
    path = generator.render_html_report(
        compliance_result=compliance_res,
        correlated_findings=correlated,
        target_name="Test Web App",
        output_filepath=out_file
    )

    assert os.path.exists(path)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "سامانه ارزیابی امنیتی و صدور انطباق افتا" in content
