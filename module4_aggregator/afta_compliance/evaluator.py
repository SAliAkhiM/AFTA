import json
import os
from typing import List, Dict, Any
from common.models import Finding, Severity


class AFTAEvaluator:
    """
    Evaluates aggregated security findings against official AFTA security requirements.
    Calculates compliance scorecards and pass/fail verdicts.
    """

    def __init__(
        self,
        controls_path: str = None,
        cwe_mapping_path: str = None
    ):
        base_dir = os.path.dirname(__file__)
        self.controls_path = controls_path or os.path.join(base_dir, "afta_controls.json")
        self.cwe_mapping_path = cwe_mapping_path or os.path.join(base_dir, "cwe_mapping.json")

        with open(self.controls_path, "r", encoding="utf-8") as f:
            self.controls = json.load(f)

        with open(self.cwe_mapping_path, "r", encoding="utf-8") as f:
            self.cwe_mapping = json.load(f)

    def evaluate(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Evaluates a list of findings against AFTA controls.
        """
        control_results: Dict[str, Dict[str, Any]] = {}
        for c in self.controls:
            cid = c["control_id"]
            control_results[cid] = {
                "control": c,
                "status": "PASS",
                "violations": [],
                "severity_counts": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFO": 0
                }
            }

        unmapped_findings: List[Finding] = []

        for f in findings:
            cid = None
            if f.cwe_id:
                cid = self.cwe_mapping.get(str(f.cwe_id))

            # Heuristics if CWE was not directly mapped
            if not cid:
                if f.metadata.package_name or "CVE-" in f.rule_id:
                    cid = "AFTA-DEP-01"
                elif any(k in f.rule_id.lower() or k in f.title.lower() for k in ["secret", "password", "key", "token"]):
                    cid = "AFTA-AUTH-01"
                elif any(k in f.rule_id.lower() or k in f.title.lower() for k in ["sql", "inject"]):
                    cid = "AFTA-INP-01"
                elif any(k in f.rule_id.lower() or k in f.title.lower() for k in ["xss", "cross-site"]):
                    cid = "AFTA-INP-02"

            if cid and cid in control_results:
                res = control_results[cid]
                res["violations"].append(f)
                sev_key = f.severity.value
                res["severity_counts"][sev_key] += 1

                # Update status
                if sev_key in ("CRITICAL", "HIGH"):
                    res["status"] = "FAIL"
                elif res["status"] != "FAIL":
                    res["status"] = "WARNING"
            else:
                unmapped_findings.append(f)

        # Summary statistics
        total_controls = len(self.controls)
        passed_controls = sum(1 for r in control_results.values() if r["status"] == "PASS")
        failed_controls = sum(1 for r in control_results.values() if r["status"] == "FAIL")
        warning_controls = sum(1 for r in control_results.values() if r["status"] == "WARNING")

        score_percentage = round((passed_controls / total_controls) * 100, 1)

        total_critical = sum(r["severity_counts"]["CRITICAL"] for r in control_results.values())
        total_high = sum(r["severity_counts"]["HIGH"] for r in control_results.values())
        total_medium = sum(r["severity_counts"]["MEDIUM"] for r in control_results.values())
        total_low = sum(r["severity_counts"]["LOW"] for r in control_results.values())

        if total_critical > 0 or total_high > 1:
            verdict = "عدم انطباق و مردود (FAILED)"
            verdict_code = "FAILED"
            verdict_description = "به دلیل کشف آسیب‌پذیری‌های بحرانی یا با شدت بالا، نرم‌افزار واجد شرایط دریافت تأییدیه افتا نمی‌باشد."
        elif total_high == 1 or total_medium > 2:
            verdict = "تأیید مشروط (CONDITIONAL PASS)"
            verdict_code = "CONDITIONAL"
            verdict_description = "سیستم دارای آسیب‌پذیری‌های سطح متوسط است و نیاز به اعمال اقدامات اصلاحی ظرف مدت ۳۰ روز دارد."
        else:
            verdict = "انطباق کامل و قبولی (PASSED)"
            verdict_code = "PASSED"
            verdict_description = "سیستم موفق به کسب الزامات امنیتی سطح پذیرش افتا گردیده است."

        return {
            "verdict": verdict,
            "verdict_code": verdict_code,
            "verdict_description": verdict_description,
            "compliance_score": score_percentage,
            "total_controls": total_controls,
            "passed_controls": passed_controls,
            "failed_controls": failed_controls,
            "warning_controls": warning_controls,
            "total_violations": len(findings),
            "severity_summary": {
                "CRITICAL": total_critical,
                "HIGH": total_high,
                "MEDIUM": total_medium,
                "LOW": total_low
            },
            "controls_detail": control_results,
            "unmapped_findings": unmapped_findings
        }
