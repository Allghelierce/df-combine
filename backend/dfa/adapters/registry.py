"""Adapter registry. Add new tool adapters here."""
from __future__ import annotations

from ..config import Settings
from .base import ToolAdapter, ToolStatus
from .cve_lookup import CveLookupAdapter
from .cwe_checker import CweCheckerAdapter
from .fwanalyzer import FwAnalyzerAdapter

ADAPTER_CLASSES: list[type[ToolAdapter]] = [CveLookupAdapter, FwAnalyzerAdapter, CweCheckerAdapter]


def get_adapters(settings: Settings) -> list[ToolAdapter]:
    return [cls(settings) for cls in ADAPTER_CLASSES]


def builtin_status() -> ToolStatus:
    return ToolStatus(name="builtin", display_name="Built-in analyzers", available=True,
                      detail="Format identification, safe extraction, secrets/config/drone/binary/component "
                             "scanners (always available, run inside the sandbox)",
                      mode="sandbox", inputs="Any supported firmware format")


def all_statuses(settings: Settings) -> list[dict]:
    out = [builtin_status().to_dict()]
    for a in get_adapters(settings):
        try:
            out.append(a.status().to_dict())
        except Exception as exc:  # noqa: BLE001
            out.append(ToolStatus(name=a.name, display_name=a.display_name, available=False,
                                  detail=f"status check failed: {exc}").to_dict())
    return out
