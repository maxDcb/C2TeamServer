from __future__ import annotations

import sys
from pathlib import Path


def ensure_agent_core_path() -> None:
    vendor_root = Path(__file__).resolve().parents[2] / "vendor" / "PentestAssistant"
    if vendor_root.exists():
        vendor_path = str(vendor_root)
        if vendor_path not in sys.path:
            sys.path.insert(0, vendor_path)
