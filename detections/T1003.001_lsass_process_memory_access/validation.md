# Validation

## Unit test against fixtures

`tests/fixtures/t1003_001_lsass_memory_access.json` contains synthetic events representing LSASS access attempts.

| Fixture | Shape | Expected |
|---|---|---|
| `tp_unsigned_temp_procdump` | Unsigned `procdump.exe` in `\Temp\` accessing `lsass.exe` | Fire, High (score 130) |
| `tp_masquerading_taskmgr` | Unsigned `taskmgr.exe` in `\Downloads\` | Fire, High (score 130) |
| `tp_signed_procdump_user_dir` | Signed `procdump.exe` in `\AppData\` | Fire, High (score 100) |
| `fp_system_taskmgr` | Signed `taskmgr.exe` in `System32` | Fire, Low (score 35) |
| `fp_edr_agent_allowlisted` | `msense.exe` accessing LSASS | No fire, allowlisted |

Run: `python tools/run_tests.py T1003.001`

The `fp_system_taskmgr` fixture is not fully suppressed because Task Manager can be legitimately abused to dump LSASS. It scores Low (35) as it executes from the correct path and is signed, but it is retained for visibility.

## Live validation on a lab host

1. Run the baseline query to ensure normal activity is accounted for.
2. Download Sysinternals Procdump on a lab VM.
3. Execute `procdump.exe -accepteula -ma lsass.exe lsass.dmp` from a user directory.
4. Verify the primary query triggers a High severity alert.
5. Open Task Manager, right-click the Local Security Authority Process, and select "Create dump file".
6. Verify the query captures this event (expected Low severity).

## Atomic Red Team

Relevant Atomics for T1003.001 involve dumping LSASS using `procdump`, `comsvcs.dll`, or `taskmgr.exe`.
- **T1003.001 - Dump LSASS.exe Memory using ProcDump:** Executes `procdump.exe` against LSASS. Highly effective for validating this rule.
- **T1003.001 - Dump LSASS.exe Memory using comsvcs.dll:** Uses `rundll32.exe`. The rule will flag `rundll32.exe` as a suspicious accessor if it accesses LSASS memory.

## Known limitations

- **Legitimate system tools:** Attackers exploiting legitimate system binaries (like a hijacked signed service) to dump LSASS might only trigger a Low or Medium alert if the binary runs from `System32` and lacks a suspicious name.
- **Kernel-level dumping:** Advanced malware may use kernel drivers (BYOVD) to bypass user-mode API hooking, potentially blinding Defender's `ProcessAccessed` telemetry entirely.
- **Direct system calls:** Tools implementing direct NT system calls (SysWhispers, etc.) might bypass user-land API monitoring, resulting in no telemetry in `DeviceEvents`.
