#!/usr/bin/env python3
"""
Fixture tests for the detection logic in this repository.

What this does and does not prove
---------------------------------
This harness reimplements each rule's scoring logic in Python and runs it against the synthetic
events in tests/fixtures/. It proves that the LOGIC classifies known-good and known-bad events
correctly. It does NOT execute KQL, so it cannot catch a KQL syntax error or a field name that
does not exist in the real Defender schema. Those are caught by running the query in advanced
hunting, which is what validation.md documents per rule.

Stated plainly because a test suite that implies more coverage than it has is worse than none.

Usage:
    python tools/run_tests.py                  # all rules
    python tools/run_tests.py T1204.004        # one rule, by substring match
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"

# Actors excluded by policy rather than by rule logic. See notes.md for why exclusion is by
# actor and never by folder or keyword.
ACTOR_ALLOWLIST = {"svc-mailmigration@lab.example"}


# --------------------------------------------------------------------------------------
# T1204.004 - ClickFix RunMRU
# --------------------------------------------------------------------------------------

INTERPRETERS = ["powershell", "pwsh", "cmd /c", "cmd.exe /c", "mshta", "wscript",
                "cscript", "rundll32", "regsvr32", "msiexec", "conhost", "forfiles"]
DOWNLOADERS = ["curl ", "certutil", "bitsadmin", "invoke-webrequest", "iwr ", "wget ",
               "downloadstring", "downloadfile", "http://", "https://"]
OBFUSCATION = ["-enc", "-encodedcommand", "frombase64string", "iex", "invoke-expression",
               "-w hidden", "-windowstyle hidden", "-executionpolicy bypass", "-nop", "-noprofile"]

B64_BLOB = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")


def score_runmru(event: dict) -> dict:
    if event.get("ActionType") != "RegistryValueSet":
        return {"fires": False}
    if r"\Explorer\RunMRU" not in event.get("RegistryKey", ""):
        return {"fires": False}

    typed = str(event.get("RegistryValueData", ""))
    cmd = typed.lower()

    has_interp = any(t in cmd for t in INTERPRETERS)
    has_dl = any(t in cmd for t in DOWNLOADERS)
    has_obf = any(t in cmd for t in OBFUSCATION)

    if not (has_interp or has_dl or has_obf):
        return {"fires": False}

    score = (40 if has_interp else 0)
    score += (30 if has_dl else 0)
    score += (40 if has_obf else 0)
    # An interpreter AND a remote fetch in the same pasted string is the ClickFix shape itself.
    # Neither half alone is damning; together they are close to never benign.
    score += (20 if (has_interp and has_dl) else 0)
    score += (20 if len(typed) > 120 else 0)
    score += (30 if B64_BLOB.search(typed) else 0)

    return {
        "fires": True,
        "score": score,
        "severity": "High" if score >= 90 else "Medium" if score >= 50 else "Low",
        "signals": {"interpreter": has_interp, "downloader": has_dl, "obfuscation": has_obf},
    }


# --------------------------------------------------------------------------------------
# T1114.003 - mailbox rule forwarding or hiding
# --------------------------------------------------------------------------------------

SUPPRESSION_FOLDERS = {"rss feeds", "rss subscriptions", "conversation history",
                       "deleted items", "junk email", "archive", "notes", "sync issues"}
HIGH_RISK_KEYWORDS = ["invoice", "payment", "remittance", "wire", "bank", "swift", "iban",
                      "purchase order", "vendor", "supplier", "password", "verify", "mfa",
                      "authenticator", "one-time", "otp", "phish", "suspicious",
                      "security alert", "helpdesk"]
RULE_ACTIONS = {"New-InboxRule", "Set-InboxRule", "UpdateInboxRules"}


def score_inbox_rule(event: dict, accepted_domains: list[str]) -> dict:
    if event.get("ActionType") not in RULE_ACTIONS:
        return {"fires": False}

    p = event.get("Parameters", {})
    forward_target = " ".join(
        str(p.get(k, "")) for k in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
    ).strip().lower()

    keyword_blob = " ".join(
        str(p.get(k, "")) for k in ("SubjectContainsWords", "BodyContainsWords",
                                    "SubjectOrBodyContainsWords", "FromAddressContainsWords")
    ).lower()

    forwards_externally = bool(forward_target) and not any(
        d.lower() in forward_target for d in accepted_domains
    )
    suppresses = (str(p.get("MoveToFolder", "")).lower() in SUPPRESSION_FOLDERS
                  or str(p.get("DeleteMessage", "")).lower() == "true")
    high_risk_kw = any(k in keyword_blob for k in HIGH_RISK_KEYWORDS)

    if not (forwards_externally or suppresses):
        return {"fires": False}

    name = str(p.get("Name", "")).strip()
    score = (50 if forwards_externally else 0)
    score += (30 if suppresses else 0)
    score += (20 if high_risk_kw else 0)
    score += (10 if str(p.get("MarkAsRead", "")).lower() == "true" else 0)
    score += (15 if name in ("", ".", "..", "-", "_") else 0)

    result = {
        "fires": True,
        "score": score,
        "severity": "High" if score >= 80 else "Medium" if score >= 50 else "Low",
        "signals": {"forwards_externally": forwards_externally,
                    "suppresses": suppresses,
                    "high_risk_keywords": high_risk_kw},
    }
    if event.get("AccountId") in ACTOR_ALLOWLIST:
        result["suppressed_by"] = "actor_allowlist"
    return result


# --------------------------------------------------------------------------------------
# T1219 - RMM tooling from a user writable path
# --------------------------------------------------------------------------------------

RMM_BINARIES = {"screenconnect.clientservice.exe", "screenconnect.windowsclient.exe",
                "anydesk.exe", "teamviewer.exe", "ateraagent.exe", "splashtopstreamer.exe",
                "syncro.exe", "rustdesk.exe", "ngrok.exe", "gotohttp.exe",
                "remoteutilities.exe", "supremo.exe", "dwagent.exe", "meshagent.exe",
                "action1_agent.exe"}
USER_WRITABLE = ["\\appdata\\", "\\users\\public\\", "\\downloads\\", "\\temp\\", "\\programdata\\"]
DELIVERY_PARENTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                    "mshta.exe", "msiexec.exe", "outlook.exe", "winword.exe", "excel.exe",
                    "chrome.exe", "msedge.exe", "firefox.exe", "explorer.exe"}


def score_rmm(event: dict, fixture: dict) -> dict:
    name = str(event.get("FileName", "")).lower()
    if name not in RMM_BINARIES or name in {s.lower() for s in fixture.get("sanctioned_rmm", [])}:
        return {"fires": False}

    path = str(event.get("FolderPath", "")).lower()
    from_user_writable = any(frag in path for frag in USER_WRITABLE)
    from_sanctioned = any(path.startswith(p.lower()) for p in fixture.get("sanctioned_paths", []))
    delivery_parent = str(event.get("InitiatingProcessFileName", "")).lower() in DELIVERY_PARENTS
    unsigned = str(event.get("ProcessVersionInfoCompanyName", "")) == ""

    if not (from_user_writable or delivery_parent):
        return {"fires": False}

    score = (40 if from_user_writable else 0)
    score += (35 if delivery_parent else 0)
    score += (0 if from_sanctioned else 15)
    score += (20 if unsigned else 0)
    return {
        "fires": True,
        "score": score,
        "severity": "High" if score >= 75 else "Medium" if score >= 40 else "Low",
        "signals": {"user_writable": from_user_writable, "delivery_parent": delivery_parent,
                    "unsigned": unsigned},
    }


# --------------------------------------------------------------------------------------
# T1656 - external Teams contact after mail bombing
# --------------------------------------------------------------------------------------

SUPPORT_PERSONA = ["help desk", "helpdesk", "it support", "it desk", "service desk",
                   "support team", "technical support", "security team", "it team",
                   "microsoft support", "office 365 support"]


def _ts(value):
    from datetime import datetime, timezone
    if not value:
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=timezone.utc)


def score_teams_impersonation(event: dict, fixture: dict) -> dict:
    if event.get("MailCount", 0) < fixture.get("bomb_threshold", 40):
        return {"fires": False}
    if event.get("SenderDomains", 0) < fixture.get("distinct_sender_domains", 15):
        return {"fires": False}

    chat_time = _ts(event.get("ChatTime"))
    bomb_end = _ts(event.get("BombEnd"))
    if chat_time is None or bomb_end is None:
        return {"fires": False}

    sender_domain = str(event.get("SenderDomain") or "").lower()
    if sender_domain in {d.lower() for d in fixture.get("trusted_support_tenants", [])}:
        return {"fires": False}

    minutes_after = (chat_time - bomb_end).total_seconds() / 60
    if minutes_after < 0 or minutes_after > fixture.get("correlation_window_minutes", 480):
        return {"fires": False}

    display = str(event.get("SenderDisplay") or "").lower()
    impersonates = any(p in display for p in SUPPORT_PERSONA)

    score = 60
    score += (30 if impersonates else 0)
    score += (20 if minutes_after <= 60 else 0)
    score += (10 if event.get("MailCount", 0) >= 150 else 0)
    return {
        "fires": True,
        "score": score,
        "severity": "High" if score >= 90 else "Medium" if score >= 60 else "Low",
        "signals": {"impersonates_support": impersonates,
                    "minutes_after_bomb": int(minutes_after)},
    }


# --------------------------------------------------------------------------------------
# T1566.002 - phishing click from a non prevalent sender
# --------------------------------------------------------------------------------------

CREDENTIAL_KEYWORDS = ["login", "signin", "sign-in", "auth", "verify", "verification",
                       "secure", "account", "password", "portal", "office", "microsoft",
                       "owa", "sso", "mfa"]
BLOCKED_ACTIONS = {"ClickBlocked", "ClickBlockedByTenantPolicy"}


def score_phishing_click(event: dict, fixture: dict) -> dict:
    if event.get("ActionType") in BLOCKED_ACTIONS:
        return {"fires": False}

    domain = str(event.get("SenderFromDomain", "")).lower()
    if domain in {d.lower() for d in fixture.get("simulation_senders", [])}:
        return {"fires": False}
    if domain in {d.lower() for d in fixture.get("known_sender_domains", [])}:
        return {"fires": False}

    url = str(event.get("Url", "")).lower()
    lands_on_auth = any(k in url for k in CREDENTIAL_KEYWORDS)
    delivered = str(event.get("DeliveryAction", "")).lower() == "delivered"
    many_urls = event.get("UrlCount", 0) >= 8

    click_time = _ts(event.get("ClickTime"))
    mail_time = _ts(event.get("MailTime"))
    minutes_to_click = (click_time - mail_time).total_seconds() / 60 if click_time and mail_time else 9999

    score = 40
    score += (30 if lands_on_auth else 0)
    score += (15 if delivered else 0)
    score += (10 if many_urls else 0)
    score += (15 if minutes_to_click <= 10 else 0)
    return {
        "fires": True,
        "score": score,
        "severity": "High" if score >= 85 else "Medium" if score >= 55 else "Low",
        "signals": {"lands_on_auth_page": lands_on_auth, "delivered": delivered,
                    "minutes_to_click": int(minutes_to_click)},
    }


SCORERS = {
    "t1204_004_runmru.json": lambda e, fx: score_runmru(e),
    "t1114_003_inbox_rule.json": lambda e, fx: score_inbox_rule(e, fx.get("accepted_domains", [])),
    "t1219_rmm.json": score_rmm,
    "t1656_teams_impersonation.json": score_teams_impersonation,
    "t1566_002_phishing_click.json": score_phishing_click,
}


def main() -> int:
    needle = sys.argv[1] if len(sys.argv) > 1 else ""
    passed = failed = 0

    for path in sorted(FIXTURES.glob("*.json")):
        fixture = json.loads(path.read_text())
        if needle and needle.lower() not in fixture["rule"].lower():
            continue
        scorer = SCORERS.get(path.name)
        if scorer is None:
            print(f"  !  no scorer registered for {path.name}, skipping")
            continue

        print(f"\n{fixture['rule']}  ({fixture['table']})")
        for event in fixture["events"]:
            expected = event["_expected"]
            actual = scorer(event, fixture)
            problems = [
                f"{key}: expected {value!r}, got {actual.get(key)!r}"
                for key, value in expected.items()
                if actual.get(key) != value
            ]
            if problems:
                failed += 1
                print(f"  FAIL  {event['_id']}")
                for problem in problems:
                    print(f"          {problem}")
            else:
                passed += 1
                detail = f"score {actual['score']} {actual['severity']}" if actual["fires"] else "no fire"
                print(f"  ok    {event['_id']:<32} {detail}")

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
