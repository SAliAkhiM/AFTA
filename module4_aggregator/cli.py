import argparse
import sys
import os
from typing import List
from common.models import Finding
from module4_aggregator.ingestion.parser import ScanParser
from module4_aggregator.correlation.correlator import Correlator
from module4_aggregator.afta_compliance.evaluator import AFTAEvaluator
from module4_aggregator.reporting.report_generator import ReportGenerator


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        prog="afta-aggregator",
        description="AFTA Module 4: Ingestion, Correlation & Compliance Audit Report Generator"
    )
    parser.add_argument("--sast", help="Path to SAST scan JSON (Module 1)")
    parser.add_argument("--dast", help="Path to DAST scan JSON (Module 2)")
    parser.add_argument("--sca", help="Path to SCA scan JSON (Module 3)")
    parser.add_argument("--target-name", default="سامانه تحت ارزیابی", help="Target project or application name")
    parser.add_argument("--output", "-o", default="afta_compliance_report.html", help="Path to save HTML report")

    args = parser.parse_args()

    if not (args.sast or args.dast or args.sca):
        print("Error: At least one scan report (--sast, --dast, or --sca) must be provided.", file=sys.stderr)
        sys.exit(1)

    sast_findings: List[Finding] = []
    dast_findings: List[Finding] = []
    sca_findings: List[Finding] = []

    if args.sast and os.path.exists(args.sast):
        print(f"[*] Ingesting SAST report: {args.sast}")
        sast_report = ScanParser.parse_file(args.sast)
        sast_findings = sast_report.findings

    if args.dast and os.path.exists(args.dast):
        print(f"[*] Ingesting DAST report: {args.dast}")
        dast_report = ScanParser.parse_file(args.dast)
        dast_findings = dast_report.findings

    if args.sca and os.path.exists(args.sca):
        print(f"[*] Ingesting SCA report: {args.sca}")
        sca_report = ScanParser.parse_file(args.sca)
        sca_findings = sca_report.findings

    print(f"[*] Correlating findings across {len(sast_findings)} SAST, {len(dast_findings)} DAST, {len(sca_findings)} SCA items...")
    correlated = Correlator.correlate(sast_findings, dast_findings, sca_findings)

    print("[*] Evaluating findings against official AFTA controls...")
    all_findings = [item.finding for item in correlated]
    evaluator = AFTAEvaluator()
    compliance_result = evaluator.evaluate(all_findings)

    print(f"[+] Compliance Score: {compliance_result['compliance_score']}% | Verdict: {compliance_result['verdict']}")

    print(f"[*] Generating official AFTA report...")
    generator = ReportGenerator()
    out_path = generator.render_html_report(
        compliance_result=compliance_result,
        correlated_findings=correlated,
        target_name=args.target_name,
        output_filepath=args.output
    )

    print(f"[+] Successfully generated report: {out_path}")


if __name__ == "__main__":
    main()
