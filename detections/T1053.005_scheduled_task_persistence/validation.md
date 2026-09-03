# Validation

## Unit test against fixtures

`tests/fixtures/t1053_005_scheduled_task.json` contains synthetic process events for `schtasks.exe` creation.

| Fixture | Shape | Expected |
|---|---|---|
| `tp_powershell_task_from_temp` | Unsigned binary in `\Temp\` creates task running `powershell.exe` | Fire, High (score 130) |
| `tp_cmd_task` | Script creates task running `cmd.exe /c` | Fire, Medium (score 80) |
| `fp_browser_updater` | Signed updater creates routine task | No fire, allowlisted |
| `fp_signed_admin_tool` | Signed tool in `System32` creates task | Fire, Low (score 40) |

Run: `python tools/run_tests.py T1053.005`

## Live validation on a lab host

1. On a lab machine, open an administrative command prompt.
2. Execute `schtasks /create /tn "TestPersistence" /tr "cmd.exe /c calc.exe" /sc onlogon /ru System`
3. Verify that `DeviceProcessEvents` captures the execution of `schtasks.exe` and the query generates an alert.
4. Clean up: `schtasks /delete /tn "TestPersistence" /f`

## Atomic Red Team

Relevant Atomics for T1053.005:
- **T1053.005 - Scheduled Task Startup Script:** Uses `schtasks.exe` to create a persistence mechanism.
- **T1053.005 - Scheduled task Local:** Uses `schtasks.exe` to run a task locally.

These tests directly trigger this rule's command-line detection logic.

## Known limitations

- **COM/API creation:** The rule relies on the execution of the `schtasks.exe` binary. If an attacker uses the Task Scheduler COM interface directly (which is common in advanced malware and PowerShell cmdlets like `Register-ScheduledTask`), `schtasks.exe` is never executed, and the rule will not fire.
- **Obfuscation:** Command-line obfuscation (e.g. inserting carets `s^c^h^t^a^s^k^s`) might bypass simplistic command-line matches, though Defender's `ProcessCommandLine` often standardizes parsing.
