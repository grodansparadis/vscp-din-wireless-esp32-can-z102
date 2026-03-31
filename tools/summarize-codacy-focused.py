#!/usr/bin/env python3

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = ROOT / "codacy-focused"
REPORTS = [
    REPORT_DIR / "opengrep.sarif",
    REPORT_DIR / "lizard.sarif",
    REPORT_DIR / "trivy.sarif",
]

SKIP_PARTS = [
    "managed_components/",
    "third_party/",
    "node_modules/",
    ".venv/",
    "firmware/test/ws/",
    "/build/",
    ".codacy/",
]

KEEP_PREFIXES = [
    "firmware/main/",
    "firmware/tools/",
    ".github/",
    "tools/",
]


def keep_path(path: str) -> bool:
    if any(part in path for part in SKIP_PARTS):
        return False
    return any(path.startswith(prefix) for prefix in KEEP_PREFIXES)


def normalize_uri(uri: str) -> str:
    marker = "vscp-din-wireless-esp32-can-z102/"
    if marker in uri:
        return uri.split(marker, 1)[1]
    return uri.replace("file://", "")


def main() -> int:
    findings = []

    for report in REPORTS:
        if not report.exists():
            continue

        with report.open() as handle:
            sarif = json.load(handle)

        for run in sarif.get("runs", []):
            tool = run.get("tool", {}).get("driver", {}).get("name", report.stem)
            for result in run.get("results", []):
                message = result.get("message", {}).get("text", "")
                rule_id = result.get("ruleId", "")
                level = result.get("level", "warning")
                for loc in result.get("locations", []):
                    physical = loc.get("physicalLocation", {})
                    uri = normalize_uri(physical.get("artifactLocation", {}).get("uri", ""))
                    line = physical.get("region", {}).get("startLine", 0)
                    if keep_path(uri):
                        findings.append((level, tool, uri, line, rule_id, message))

    severity_rank = {"error": 0, "warning": 1, "note": 2, "none": 3}
    findings.sort(key=lambda item: (severity_rank.get(item[0], 9), item[2], item[3], item[1]))

    print(f"Actionable findings: {len(findings)}")
    for level, tool, uri, line, rule_id, message in findings:
        print(f"[{level}] {tool} {uri}:{line} ({rule_id}) {message}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())