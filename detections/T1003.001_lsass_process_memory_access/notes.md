# LSASS process memory access

| | |
|---|---|
| **ATT&CK** | T1003.001 OS Credential Dumping: LSASS Memory |
| **Tactic** | Credential Access |
| **Data source** | `DeviceEvents` |
| **Status** | Validated against fixtures |

## Background & Hypothesis

Extracting credential material from Windows usually requires reading the memory of the Local Security Authority Subsystem Service (LSASS). EDR products heavily monitor access to `lsass.exe`. If a non-system, unrecognised, or user-space process requests read access to LSASS, it is highly likely to be credential dumping behaviour.

## How we score this

The baseline risk for an unrecognised process reading LSASS memory is low to medium, as some legacy applications and administrative tools do this legitimately. The score is escalated by several context signals:

1. **Unsigned process (+30):** Legitimate software reading LSASS is almost universally signed by Microsoft or an established enterprise software vendor.
2. **Suspicious name (+35):** Binaries masquerading as system tools (like `taskmgr.exe` in the wrong folder) or known dumping tools (like `procdump.exe` or `mimikatz.exe`) represent clear intent.
3. **User-writable path (+40):** A process executing from `\AppData\Local\Temp\` or `\Downloads\` and immediately requesting LSASS access is characteristic of commodity malware and hands-on-keyboard post-exploitation.
4. **Not a system location (+25):** Core Windows processes that interact with LSASS execute from protected directories like `System32`.

## Common False Positives, ranked by how often they occur

1. **Endpoint Detection and Response (EDR) agents:** They inherently monitor LSASS for the exact behaviour this rule looks for, requiring memory access. These must be allowlisted during the baseline phase.
2. **Enterprise management and inventory agents:** Tools like SCCM or vulnerability scanners sometimes inspect running processes heavily.
3. **Task Manager:** `taskmgr.exe` allows a user to right-click and "Create dump file". This is a real dumping technique but also a legitimate troubleshooting action. Context (who ran it, from where) differentiates the two.
4. **Legacy applications:** Some older software indiscriminately requests `PROCESS_ALL_ACCESS` when querying system state, inadvertently triggering access alarms on LSASS.

## Triage Guide

1. Review the `AccessorPath` and `Unsigned` status. An unsigned binary in a user directory is malicious until proven otherwise.
2. Check the `CommandLine` of the accessor. `procdump.exe -accepteula -ma lsass.exe` is conclusive.
3. Run the enrichment query to check if the accessor wrote a `.dmp` file shortly after accessing LSASS.
4. Identify the parent process. Was the accessor spawned by a shell, a macro, or an RMM tool?
5. Determine if the file was recently downloaded or dropped (check `DeviceFileEvents` for the `AccessorPath`).

## Response / Remediation

1. Isolate the affected device immediately to prevent lateral movement.
2. Assume the credentials of all users currently logged into or recently active on the machine have been compromised.
3. Force a password reset and revoke session tokens for those users.
4. Search the estate for the accessor hash to identify other compromised hosts.
5. If a dump file was created, trace its exfiltration (check `DeviceNetworkEvents` or archiving activity).

## Deployment notes

- **Baseline first:** Do not deploy this rule without running the baseline query. The default `AllowedAccessors` list is illustrative, not exhaustive. Your environment's EDR and management agents will cause a flood of alerts if not added.
- The rule relies on the `DeviceEvents` table and `ActionType` representing process access. The specific API calls logged (e.g. `ReadProcessMemoryApiCall`) depend on Defender's internal telemetry generation.
