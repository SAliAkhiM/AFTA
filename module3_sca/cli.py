import argparse
import json
import os
import sys
from module3_sca.sca_engine import SCAEngine


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        prog="afta-sca",
        description="AFTA Module 3: Software Composition Analysis (SCA) & CycloneDX SBOM Generator"
    )
    parser.add_argument("target", help="Path to project directory or manifest file")
    parser.add_argument(
        "--output", "-o",
        default="sca_findings.json",
        help="Path to save the Unified Data Contract JSON report (default: sca_findings.json)"
    )
    parser.add_argument(
        "--sbom", "-s",
        default="sbom.json",
        help="Path to save the CycloneDX SBOM JSON (default: sbom.json)"
    )
    parser.add_argument(
        "--no-remote",
        action="store_true",
        help="Disable remote API lookups (offline mode)"
    )

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"Error: Target path '{args.target}' does not exist.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Starting AFTA SCA scan on: {args.target}")
    engine = SCAEngine(use_remote_apis=not args.no_remote)
    results = engine.scan_path(args.target)

    # Save Unified Data Contract report
    report_data = results["report"].model_dump()
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    print(f"[+] Scan report saved to: {args.output}")

    # Save CycloneDX SBOM
    with open(args.sbom, "w", encoding="utf-8") as f:
        json.dump(results["sbom"], f, indent=2, ensure_ascii=False)
    print(f"[+] CycloneDX SBOM saved to: {args.sbom}")

    total_findings = len(results["report"].findings)
    print(f"[+] Scan completed. Discovered {total_findings} vulnerable dependencies.")


if __name__ == "__main__":
    main()
