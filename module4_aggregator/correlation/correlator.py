from typing import List, Dict, Any, Tuple
from common.models import Finding, Severity


class CorrelatedFinding:
    def __init__(
        self,
        primary_finding: Finding,
        sources: List[str],
        is_cross_verified: bool = False,
        cross_verification_note: str = ""
    ):
        self.finding = primary_finding
        self.sources = sources
        self.is_cross_verified = is_cross_verified
        self.cross_verification_note = cross_verification_note


class Correlator:
    """
    Correlates findings across different scanner modules (e.g. SAST + DAST + SCA).
    Performs cross-verification when a dynamic vulnerability (DAST) matches a static code flaw (SAST).
    """

    @staticmethod
    def correlate(
        sast_findings: List[Finding],
        dast_findings: List[Finding],
        sca_findings: List[Finding]
    ) -> List[CorrelatedFinding]:
        results: List[CorrelatedFinding] = []
        matched_dast_indexes = set()

        for sast in sast_findings:
            matched_dast = None
            for idx, dast in enumerate(dast_findings):
                if idx in matched_dast_indexes:
                    continue

                # Condition 1: Same CWE ID (and not None)
                if sast.cwe_id and dast.cwe_id and (sast.cwe_id == dast.cwe_id):
                    # Condition 2: Keyword match in endpoint vs file path
                    sast_path = (sast.location.path_or_url or "").lower()
                    dast_url = (dast.location.path_or_url or "").lower()

                    # e.g., "auth" in both or "user" in both or "login" in both
                    sast_tokens = set(filter(lambda x: len(x) > 3, sast_path.replace("\\", "/").split("/")))
                    dast_tokens = set(filter(lambda x: len(x) > 3, dast_url.split("?")[0].split("/")))

                    if sast_tokens.intersection(dast_tokens) or sast.cwe_id in {89, 79, 352}:
                        # Cross-verification confirmed!
                        matched_dast = dast
                        matched_dast_indexes.add(idx)
                        break

            if matched_dast:
                note = (
                    f"تأیید متقابل دوگانه (Cross-Verified): این آسیب‌پذیری هم در سورس‌کد "
                    f"({sast.location.path_or_url}) و هم در زمان اجرا در اندپوینت "
                    f"({matched_dast.location.path_or_url}) کشف و اثبات شده است."
                )
                # Boost severity if not already Critical
                boosted = sast.model_copy(deep=True)
                if boosted.severity == Severity.HIGH:
                    boosted.severity = Severity.CRITICAL

                results.append(
                    CorrelatedFinding(
                        primary_finding=boosted,
                        sources=["SAST", "DAST"],
                        is_cross_verified=True,
                        cross_verification_note=note
                    )
                )
            else:
                results.append(
                    CorrelatedFinding(
                        primary_finding=sast,
                        sources=["SAST"],
                        is_cross_verified=False
                    )
                )

        # Add remaining unmatched DAST findings
        for idx, dast in enumerate(dast_findings):
            if idx not in matched_dast_indexes:
                results.append(
                    CorrelatedFinding(
                        primary_finding=dast,
                        sources=["DAST"],
                        is_cross_verified=False
                    )
                )

        # Add SCA findings
        for sca in sca_findings:
            results.append(
                CorrelatedFinding(
                    primary_finding=sca,
                    sources=["SCA"],
                    is_cross_verified=False
                )
            )

        return results
