import os
from datetime import datetime
from typing import List, Dict, Any
from jinja2 import Environment, FileSystemLoader
from module4_aggregator.correlation.correlator import CorrelatedFinding


class ReportGenerator:
    """
    Renders official AFTA compliance audit reports in standalone HTML format (print/PDF ready).
    """

    def __init__(self, template_dir: str = None):
        base_dir = os.path.dirname(__file__)
        self.template_dir = template_dir or os.path.join(base_dir, "templates")
        self.env = Environment(loader=FileSystemLoader(self.template_dir), autoescape=True)

    def render_html_report(
        self,
        compliance_result: Dict[str, Any],
        correlated_findings: List[CorrelatedFinding],
        target_name: str = "سامانه هدف",
        output_filepath: str = "afta_audit_report.html"
    ) -> str:
        template = self.env.get_template("report_template.html")
        cross_verified_count = sum(1 for f in correlated_findings if f.is_cross_verified)

        html_content = template.render(
            compliance=compliance_result,
            correlated_findings=correlated_findings,
            cross_verified_count=cross_verified_count,
            target_name=target_name,
            report_date=datetime.now().strftime("%Y-%m-%d %H:%M")
        )

        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        return os.path.abspath(output_filepath)
