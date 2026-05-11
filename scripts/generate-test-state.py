#!/usr/bin/env python3
"""Generate validation state documents from the test catalog and result files."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - developer setup failure
    raise SystemExit("PyYAML is required: python3 -m pip install pyyaml") from exc


VALID_RESULT_STATUSES = {"pass", "fail", "blocked", "untested"}
VALIDATION_MODES = {"auto", "manual", "auto+manual", "planned"}
PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
FINAL_ORDER = {"fail": 0, "blocked": 1, "partial": 2, "untested": 3, "planned": 4, "pass": 5}


def load_yaml(path: Path, fallback: dict[str, Any] | None = None) -> dict[str, Any]:
    if not path.exists():
        return fallback or {}
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return data


def load_auto_results(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        results = data.get("results", [])
    else:
        results = data
    if not isinstance(results, list):
        raise ValueError(f"{path} must contain a JSON list or an object with a results list")
    return results


def normalize_status(value: Any) -> str:
    status = str(value or "untested").strip().lower()
    if status not in VALID_RESULT_STATUSES:
        raise ValueError(f"invalid result status: {status}")
    return status


def index_results(
    results: list[dict[str, Any]],
    source_name: str,
    catalog_ids: set[str],
) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for result in results:
        if not isinstance(result, dict):
            raise ValueError(f"{source_name} contains a non-object result")
        result_id = str(result.get("id", "")).strip()
        if not result_id:
            raise ValueError(f"{source_name} contains a result without id")
        if result_id not in catalog_ids:
            raise ValueError(f"{source_name} references unknown catalog id: {result_id}")
        if result_id in indexed:
            raise ValueError(f"{source_name} contains duplicate result id: {result_id}")
        normalized = dict(result)
        normalized["status"] = normalize_status(result.get("status"))
        indexed[result_id] = normalized
    return indexed


def required_channels(validation: str) -> list[str]:
    if validation == "auto":
        return ["auto"]
    if validation == "manual":
        return ["manual"]
    if validation == "auto+manual":
        return ["auto", "manual"]
    return []


def final_status(validation: str, auto_status: str, manual_status: str) -> str:
    if validation == "planned":
        return "planned"

    statuses = [auto_status if channel == "auto" else manual_status for channel in required_channels(validation)]
    if not statuses:
        return "untested"
    if any(status == "fail" for status in statuses):
        return "fail"
    if any(status == "blocked" for status in statuses):
        return "blocked"
    if all(status == "pass" for status in statuses):
        return "pass"
    if any(status == "pass" for status in statuses):
        return "partial"
    return "untested"


def result_summary(result: dict[str, Any] | None) -> str:
    if not result:
        return ""
    parts = []
    for key in ("source", "evidence", "date", "build", "tester", "notes"):
        value = result.get(key)
        if value:
            parts.append(f"{key}: {value}")
    return "; ".join(parts)


def markdown_escape(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.replace("|", "\\|").replace("\n", "<br>")


def priority_key(entry: dict[str, Any]) -> tuple[int, str, str]:
    return (
        PRIORITY_ORDER.get(str(entry.get("priority", "")).lower(), 99),
        str(entry.get("area", "")),
        str(entry.get("id", "")),
    )


def state_key(row: dict[str, Any]) -> tuple[int, int, str, str]:
    return (
        FINAL_ORDER.get(row["final"], 99),
        PRIORITY_ORDER.get(row["priority"], 99),
        row["area"],
        row["id"],
    )


def build_rows(
    catalog: dict[str, Any],
    auto_results: dict[str, dict[str, Any]],
    manual_results: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    entries = catalog.get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("catalog entries must be a list")

    rows: list[dict[str, Any]] = []
    for entry in sorted(entries, key=priority_key):
        validation = str(entry.get("validation", "planned")).strip()
        if validation not in VALIDATION_MODES:
            raise ValueError(f"{entry.get('id')} has invalid validation mode: {validation}")

        entry_id = str(entry.get("id", "")).strip()
        auto_result = auto_results.get(entry_id)
        manual_result = manual_results.get(entry_id)
        auto_status = normalize_status(auto_result.get("status") if auto_result else "untested")
        manual_status = normalize_status(manual_result.get("status") if manual_result else "untested")

        rows.append(
            {
                "id": entry_id,
                "area": str(entry.get("area", "")),
                "feature": str(entry.get("feature", "")),
                "scenario": str(entry.get("scenario", "")),
                "priority": str(entry.get("priority", "")),
                "validation": validation,
                "auto": auto_status if "auto" in required_channels(validation) else "n/a",
                "manual": manual_status if "manual" in required_channels(validation) else "n/a",
                "final": final_status(validation, auto_status, manual_status),
                "auto_detail": result_summary(auto_result),
                "manual_detail": result_summary(manual_result),
                "axes": entry.get("axes", {}),
            }
        )
    return rows


def write_state(path: Path, rows: list[dict[str, Any]], auto_path: Path, manual_path: Path) -> None:
    counts = Counter(row["final"] for row in rows)
    validation_counts = Counter(row["validation"] for row in rows)
    area_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        area_counts[row["area"]][row["final"]] += 1

    lines = [
        "# Test State",
        "",
        "_Generated by `scripts/generate-test-state.py`._",
        "",
        f"- Catalog entries: `{len(rows)}`",
        f"- Auto results: `{auto_path}`",
        f"- Manual results: `{manual_path}`",
        "",
        "## Final Status",
        "",
        "| Status | Count |",
        "|---|---:|",
    ]
    for status in ("pass", "fail", "blocked", "partial", "untested", "planned"):
        lines.append(f"| {status} | {counts.get(status, 0)} |")

    lines.extend(["", "## Validation Modes", "", "| Mode | Count |", "|---|---:|"])
    for mode in ("auto", "manual", "auto+manual", "planned"):
        lines.append(f"| {mode} | {validation_counts.get(mode, 0)} |")

    lines.extend(["", "## By Area", "", "| Area | Pass | Fail | Blocked | Partial | Untested | Planned | Total |", "|---|---:|---:|---:|---:|---:|---:|---:|"])
    for area in sorted(area_counts):
        counter = area_counts[area]
        total = sum(counter.values())
        lines.append(
            f"| {markdown_escape(area)} | {counter.get('pass', 0)} | {counter.get('fail', 0)} | "
            f"{counter.get('blocked', 0)} | {counter.get('partial', 0)} | "
            f"{counter.get('untested', 0)} | {counter.get('planned', 0)} | {total} |"
        )

    lines.extend(
        [
            "",
            "## Critical Non-Pass",
            "",
            "| Final | ID | Area | Feature | Auto | Manual |",
            "|---|---|---|---|---|---|",
        ]
    )
    critical_rows = [
        row for row in rows if row["priority"] == "critical" and row["final"] != "pass"
    ]
    for row in sorted(critical_rows, key=state_key):
        lines.append(
            f"| {row['final']} | `{row['id']}` | {markdown_escape(row['area'])} | "
            f"{markdown_escape(row['feature'])} | {row['auto']} | {row['manual']} |"
        )
    if not critical_rows:
        lines.append("| pass | _none_ |  |  |  |  |")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_gaps(path: Path, rows: list[dict[str, Any]]) -> None:
    gaps = [row for row in rows if row["final"] != "pass"]
    lines = [
        "# Test Gaps",
        "",
        "_Generated by `scripts/generate-test-state.py`._",
        "",
        "| Final | Priority | ID | Area | Feature | Scenario | Auto | Manual |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in sorted(gaps, key=state_key):
        lines.append(
            f"| {row['final']} | {row['priority']} | `{row['id']}` | {markdown_escape(row['area'])} | "
            f"{markdown_escape(row['feature'])} | {markdown_escape(row['scenario'])} | "
            f"{row['auto']} | {row['manual']} |"
        )
    if not gaps:
        lines.append("| pass |  | _none_ |  |  |  |  |  |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_matrix(path: Path, rows: list[dict[str, Any]]) -> None:
    lines = [
        "# Test Matrix",
        "",
        "_Generated by `scripts/generate-test-state.py`._",
        "",
        "| Final | Validation | Priority | ID | Area | Feature | OS | Arch | Listener | Artifact | Auto | Manual |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in sorted(rows, key=lambda item: (item["area"], item["feature"], item["id"])):
        axes = row.get("axes") if isinstance(row.get("axes"), dict) else {}
        lines.append(
            f"| {row['final']} | {row['validation']} | {row['priority']} | `{row['id']}` | "
            f"{markdown_escape(row['area'])} | {markdown_escape(row['feature'])} | "
            f"{markdown_escape(axes.get('os', ''))} | {markdown_escape(axes.get('arch', ''))} | "
            f"{markdown_escape(axes.get('listener', ''))} | {markdown_escape(axes.get('artifact_category', ''))} | "
            f"{row['auto']} | {row['manual']} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=Path("docs/testing/test-catalog.yaml"))
    parser.add_argument("--manual", type=Path, default=Path("docs/testing/manual-results.yaml"))
    parser.add_argument("--auto", type=Path, default=Path("build/test-results/auto-results.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("docs"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    catalog = load_yaml(args.catalog)
    entries = catalog.get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("catalog entries must be a list")

    catalog_ids = {str(entry.get("id", "")).strip() for entry in entries}
    if "" in catalog_ids:
        raise ValueError("catalog contains an entry without id")
    if len(catalog_ids) != len(entries):
        raise ValueError("catalog contains duplicate ids")

    manual_file = load_yaml(args.manual, {"results": []})
    manual_results = index_results(manual_file.get("results", []), str(args.manual), catalog_ids)
    auto_results = index_results(load_auto_results(args.auto), str(args.auto), catalog_ids)

    rows = build_rows(catalog, auto_results, manual_results)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_state(args.output_dir / "TEST_STATE.md", rows, args.auto, args.manual)
    write_gaps(args.output_dir / "TEST_GAPS.md", rows)
    write_matrix(args.output_dir / "TEST_MATRIX.md", rows)

    counts = Counter(row["final"] for row in rows)
    print(
        "Generated test state: "
        + ", ".join(f"{status}={counts.get(status, 0)}" for status in ("pass", "fail", "blocked", "partial", "untested", "planned"))
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
