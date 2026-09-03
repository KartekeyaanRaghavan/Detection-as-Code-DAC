#!/usr/bin/env python3
"""Structural checks on every Sigma rule in detections/."""

from __future__ import annotations

import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
REQUIRED = ["title", "id", "status", "description", "author", "date",
            "tags", "logsource", "detection", "falsepositives", "level"]
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}

def main() -> int:
    problems: list[str] = []
    seen_ids: dict[str, str] = {}
    rules = sorted(ROOT.glob("detections/*/rule.yml"))

    if not rules:
        print("no rules found under detections/")
        return 1

    for path in rules:
        rel = path.relative_to(ROOT)
        try:
            rule = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            problems.append(f"{rel}: invalid YAML: {exc}")
            continue

        for field in REQUIRED:
            if field not in rule:
                problems.append(f"{rel}: missing required field '{field}'")

        level = str(rule.get("level", "")).lower()
        if level and level not in VALID_LEVELS:
            problems.append(f"{rel}: level '{level}' is not a valid Sigma level")

        rule_id = rule.get("id")
        if rule_id in seen_ids:
            problems.append(f"{rel}: duplicate id, also used by {seen_ids[rule_id]}")
        elif rule_id:
            seen_ids[rule_id] = str(rel)

        tags = rule.get("tags") or []
        if not any(str(t).startswith("attack.t") for t in tags):
            problems.append(f"{rel}: no attack.tXXXX technique tag")

        detection = rule.get("detection") or {}
        if "condition" not in detection:
            problems.append(f"{rel}: detection block has no condition")

        fps = rule.get("falsepositives") or []
        if not fps or fps == ["Unknown"]:
            problems.append(f"{rel}: falsepositives must be filled in, not 'Unknown'")

        print(f"  checked {rel}")

    if problems:
        print()
        for problem in problems:
            print(f"  ERROR  {problem}")
        print(f"\n{len(problems)} problem(s) in {len(rules)} rule(s)")
        return 1

    print(f"\n{len(rules)} rule(s) OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
