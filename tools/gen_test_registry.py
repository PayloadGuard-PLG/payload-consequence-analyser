#!/usr/bin/env python3
"""Regenerate TEST_REGISTRY.md from a live pytest run. Run from repo root."""
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SUITES = ["test_analyzer.py", "tests/proofs/"]
OUT = Path("TEST_REGISTRY.md")

result = subprocess.run(
    [sys.executable, "-m", "pytest", *SUITES, "--timeout=30", "--tb=no", "-v"],
    capture_output=True, text=True,
)

lines = (result.stdout + result.stderr).splitlines()

# Parse into {class: [(test_id, status), ...]}
sections: dict[str, list[tuple[str, str]]] = {}
totals = {"passed": 0, "skipped": 0, "failed": 0}

for line in lines:
    for status in ("PASSED", "SKIPPED", "FAILED"):
        if f" {status}" in line:
            node = line.split(" " + status)[0].strip()
            # node looks like: file::Class::method  or  file::method
            parts = node.split("::")
            if len(parts) == 3:
                file_, cls, method = parts
            elif len(parts) == 2:
                file_, cls, method = parts[0], parts[0].split("/")[-1].replace(".py", ""), parts[1]
            else:
                continue
            # Shorten file prefix
            section_key = f"{file_} — {cls}"
            sections.setdefault(section_key, []).append((method, status))
            totals[status.lower()] += 1
            break

now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
total = sum(totals.values())

md_lines = [
    "# PayloadGuard — Test Registry",
    "",
    f"**Last run:** {now}  ",
    f"**Result:** {totals['passed']} passed · {totals['skipped']} skipped · {totals['failed']} failed · {total} total",
    "",
    "Run with: `python -m pytest test_analyzer.py tests/proofs/ --timeout=30 -v`  ",
    "Regenerate this file: `python tools/gen_test_registry.py`",
    "",
]

for section, tests in sections.items():
    md_lines.append(f"## {section}")
    md_lines.append("")
    for method, status in tests:
        icon = {"PASSED": "✓", "SKIPPED": "○", "FAILED": "✗"}[status]
        md_lines.append(f"- {icon} `{method}`")
    md_lines.append("")

OUT.write_text("\n".join(md_lines))
print(f"Written {OUT} — {totals['passed']} passed, {totals['skipped']} skipped, {totals['failed']} failed")
if totals["failed"]:
    sys.exit(1)
