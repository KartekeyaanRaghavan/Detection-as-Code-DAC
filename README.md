# detections-as-code

Detection engineering portfolio: Sigma rules with compiled Defender XDR KQL, analyst notes,
false positive guidance, response playbooks and validation evidence.

Written by [Kartekeyaan Raghavan](https://www.linkedin.com/in/kartekeyaan-raghavan-985a08190),
SOC analyst and shift lead on a global Microsoft Defender XDR deployment, now M.Tech Network and
Information Security at IIT Hyderabad.

Every rule here is built from **public threat intelligence and synthetic telemetry**. No employer,
customer or tenant data appears anywhere in this repository.

## Why this exists

Most detection repositories are query collections. This one is organised the way detection
engineering actually works: a rule is not finished when the query returns results. It is finished
when someone else can understand why it exists, tell a true positive from a false one, know what
to do when it fires, and see the evidence that it was tested.

Every detection therefore ships four files:

```
detections/<TECHNIQUE>_<name>/
├── rule.yml         # Sigma, the source of truth
├── detection.kql    # compiled for Defender XDR advanced hunting
├── notes.md         # hypothesis, signal weighting, FP guidance, triage, response playbook
└── validation.md    # how it was tested, and what it does not catch
```

## Coverage

| Technique | Detection | Tactic | Data source | Validated |
|---|---|---|---|---|
| [T1003.001](detections/T1003.001_lsass_process_memory_access) | LSASS process memory access | Credential Access | `DeviceEvents` | Fixtures |
| [T1114.003](detections/T1114.003_aitm_inbox_rule_exfiltration) | Mailbox rule forwarding or hiding mail after account compromise | Collection, Defense Evasion | `CloudAppEvents` | Fixtures |
| [T1204.004](detections/T1204.004_clickfix_runmru_runtime_loader) | ClickFix command pasted into the Run dialog | Execution | `DeviceRegistryEvents` | Fixtures |
| [T1219](detections/T1219_unauthorised_rmm_tooling) | RMM tooling executed from a user writable path | Command and Control | `DeviceProcessEvents` | Fixtures |
| [T1555.003](detections/T1555.003_browser_credential_store_access) | Infostealer access to browser credential stores | Credential Access | `DeviceFileEvents` | Fixtures |
| [T1566.002](detections/T1566.002_phishing_click_credential_harvest) | Click through to a credential harvesting page from a non prevalent sender | Initial Access | `UrlClickEvents`, `EmailEvents` | Fixtures |
| [T1656](detections/T1656_teams_impersonation_after_mail_bombing) | External Teams contact to a user who was just mail bombed | Initial Access | `EmailEvents`, `CloudAppEvents` | Fixtures |

Seven of a planned twenty. Two of these seven are correlation rules across two data sources rather
than single table queries, which is deliberate: several of the techniques that matter most have no
high fidelity single indicator.

Three of the seven chain together into one intrusion. A user clicks a harvesting link
(T1566.002), the operator replays the session and creates a mailbox rule (T1114.003), or a user is
mail bombed and talked into remote access over Teams (T1656 into T1219). The notes cross reference
each other where that happens.

## Roadmap

| Technique | Detection | Data source |
|---|---|---|
| T1110 | Failed logon burst followed by success | `DeviceLogonEvents` |
| T1562.001 | Defender exclusion added or tamper protection disabled | `DeviceRegistryEvents` |
| T1053.005 | Scheduled task persistence | `DeviceProcessEvents` |
| T1036.003 | Renamed system binary execution | `DeviceProcessEvents` |
| T1047 | WMI used for lateral movement | `DeviceProcessEvents` |
| T1078.004 | Sign in from an unusual ASN with a legacy auth protocol | `AADSignInEventsBeta` |
| T1098.005 | MFA method registered immediately after a password reset | `CloudAppEvents` |
| T1486 | Removable media mount followed by mass file modification | `DeviceFileEvents` |

## Using these rules

```bash
pip install pyyaml sigma-cli pysigma-backend-kusto

# convert a rule to Defender XDR KQL
sigma convert -t kusto -p microsoft_xdr detections/T1219_unauthorised_rmm_tooling/rule.yml

# validate rule structure, check every rule still converts, run the fixture tests
python tools/check_rules.py
python tools/convert_rules.py
python tools/run_tests.py
```

The checked in `detection.kql` files are not raw `sigma convert` output. They add scoring,
enrichment and tuning parameters that Sigma cannot express. The Sigma rule is the portable
definition; the KQL is the deployable artefact.

### Why three rules do not convert

`tools/convert_rules.py` converts the Windows endpoint rules and deliberately skips the
three Microsoft 365 ones. This is a limit of the public toolchain, not a defect in the rules.

The kusto backend's `microsoft_xdr` pipeline maps Sigma logsource *categories* to the
`Device*` tables. It has no mapping for `CloudAppEvents`, `EmailEvents` or `UrlClickEvents`,
and it cannot be given one by a field mapping, because the fields those rules match on -
`Operation`, `Parameters`, `CommunicationType`, `SenderDisplayName` - are not columns in
those tables. They are keys inside the `RawEventData` dynamic column, reachable only by
`parse_json` and `mv-apply`, which is what the hand written KQL does.

The Sigma rules keep the field names that SigmaHQ's own `product: m365` rules use, so they
stay portable to other backends. The skip is enforced in code and printed on every run
rather than left as a silent warning.

Before deploying anything, set the values marked `// TUNE`. Several rules ship with an empty
allow list on purpose, and at least two of them (T1219 and T1566.002) will produce an unusable
day one volume if deployed without running their baseline query first. Each `notes.md` says which.

## What this repository does not cover

Stated explicitly, because a coverage claim without a gap list is not worth reading:

- **No macOS or Linux detections.** Everything here is Windows and Microsoft 365.
- **No network layer detections.** No IDS signatures, no NetFlow, no DNS analytics.
- **No coverage of Impact tactics.** No ransomware encryption behaviour, no destruction.
- **Detection only.** No enforcement, no automated containment.
- **Seven techniques out of ATT&CK Enterprise.** The Navigator layer in `coverage/` shows what
  that looks like honestly, which is: mostly empty.
- **Validation is against synthetic fixtures**, plus lab tenant procedures documented per rule.
  These rules have not been run at production volume in this form, and per rule false positive
  rates in a real estate are unknown until they are.
- Per rule blind spots are documented in each `validation.md` rather than summarised here. The
  largest are the Graph API mailbox rule path (T1114.003), ClickFix variants that do not use the
  Run dialog (T1204.004), renamed RMM binaries (T1219), and compromised accounts at a supplier
  the organisation already trusts (T1566.002).

## Licence

MIT. Use the rules, change the thresholds, keep the gap lists honest.
