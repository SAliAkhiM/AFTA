from typing import List, Dict, Any, Tuple
from common.models import Finding


class DeduplicatedFinding:
    def __init__(self, primary_finding: Finding, source_modules: List[str]):
        self.finding = primary_finding
        self.source_modules = source_modules
        self.occurrence_count = len(source_modules)


class Deduplicator:
    """
    Deduplicates findings based on deterministic fingerprint and normalized signature.
    """

    @staticmethod
    def deduplicate(findings_with_source: List[Tuple[Finding, str]]) -> List[DeduplicatedFinding]:
        """
        Takes a list of (Finding, module_type) tuples and returns deduplicated items.
        """
        grouped: Dict[str, Tuple[Finding, List[str]]] = {}

        for finding, module_type in findings_with_source:
            key = finding.fingerprint
            if not key:
                key = Finding.create_fingerprint(
                    rule_id=finding.rule_id,
                    path_or_url=finding.location.path_or_url,
                    line_or_param=finding.location.parameter or str(finding.location.start_line)
                )

            if key not in grouped:
                grouped[key] = (finding, [module_type])
            else:
                existing_finding, modules = grouped[key]
                if module_type not in modules:
                    modules.append(module_type)

        results = [
            DeduplicatedFinding(primary_finding=f, source_modules=mods)
            for f, mods in grouped.values()
        ]
        return results
