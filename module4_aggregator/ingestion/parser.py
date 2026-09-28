import json
import os
from typing import Dict, Any, Union
from common.models import UnifiedScanReport


class ScanParser:
    """
    Ingests and validates scan outputs conforming to the Unified Data Contract.
    """

    @staticmethod
    def parse_file(filepath: str) -> UnifiedScanReport:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Scan report file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        return ScanParser.parse_dict(data)

    @staticmethod
    def parse_dict(data: Dict[str, Any]) -> UnifiedScanReport:
        return UnifiedScanReport.model_validate(data)
