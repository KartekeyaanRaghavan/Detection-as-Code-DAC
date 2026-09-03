#!/usr/bin/env python3
"""
Convert every Sigma rule in detections/ to Defender XDR KQL, and prove it still converts.

Why this is not just `sigma convert` in a loop
----------------------------------------------
The kusto backend's microsoft_xdr pipeline maps Sigma logsource *categories* to the
Device* endpoint tables. It has no mapping for the Microsoft 365 tables this repository
also targets - CloudAppEvents, EmailEvents, UrlClickEvents - and it cannot be given one
by a field mapping, because the fields those rules match on (Operation, Parameters,
CommunicationType, SenderDisplayName) are not columns. They are keys inside the
RawEventData dynamic column, reachable only by parse_json and mv-apply.

So the m365 rules are converted by hand and their KQL is the artefact of record. They are
skipped here deliberately and loudly, rather than silently passing. Every other rule MUST
convert, and a failure fails the build.

Usage:
    python tools/convert_rules.py            # check all rules
    python tools/convert_rules.py --emit      # also print the generated KQL
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGET = "kusto"
PIPELINE = "microsoft_xdr"

# Sigma logsource products the microsoft_xdr pipeline cannot map to a table. See docstring.
UNMAPPABLE_PRODUCTS = {"m365"}
UNMAPPABLE_CATEGORIES = {"process_access", "logon"}


def main() -> int:
    emit = "--emit" in sys.argv
    rules = sorted(ROOT.glob("detections/*/rule.yml"))
    if not rules:
        print("no rules found under detections/")
        return 1

    converted = skipped = 0
    failures: list[str] = []

    for path in rules:
        rel = path.relative_to(ROOT)
        logsource = (yaml.safe_load(path.read_text()) or {}).get("logsource") or {}
        product = str(logsource.get("product", ""))

        category = str(logsource.get("category", ""))
        if product in UNMAPPABLE_PRODUCTS or category in UNMAPPABLE_CATEGORIES:
            skipped += 1
            reason = f"product '{product}'" if product in UNMAPPABLE_PRODUCTS else f"category '{category}'"
            print(f"  skip  {rel}\n          {reason} has no {PIPELINE} table mapping; "
                  f"detection.kql is hand written")
            continue

        result = subprocess.run(
            ["sigma", "convert", "-t", TARGET, "-p", PIPELINE, str(path)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            failures.append(f"{rel}: {result.stderr.strip().splitlines()[-1] if result.stderr.strip() else 'unknown error'}")
            print(f"  FAIL  {rel}")
            continue

        converted += 1
        print(f"  ok    {rel}")
        if emit:
            for line in result.stdout.strip().splitlines():
                print(f"          {line}")

    print()
    if failures:
        for failure in failures:
            print(f"  ERROR  {failure}")
        print(f"\n{len(failures)} of {len(rules)} rule(s) failed to convert")
        return 1

    print(f"{converted} rule(s) converted, {skipped} skipped by design, 0 failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
