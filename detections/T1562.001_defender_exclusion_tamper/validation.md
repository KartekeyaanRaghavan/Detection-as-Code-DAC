# Validation

## Unit test against fixtures

`tests/fixtures/t1562_001_defender_evasion.json` contains synthetic registry events simulating Defender tampering.

| Fixture | Shape | Expected |
|---|---|---|
| `tp_powershell_disable_realtime` | `powershell.exe` sets `DisableRealtimeMonitoring` | Fire, High (score 110) |
| `tp_cmd_reg_add_exclusion` | `cmd.exe` adds an exclusion | Fire, High (score 90) |
| `tp_unsigned_malware_disable_tamper` | Unsigned binary in `\Temp\` disables TamperProtection | Fire, High (score 130) |
| `fp_sccm_baseline` | Authorized management tool updates exclusions | No fire, allowlisted |

Run: `python tools/run_tests.py T1562.001`

## Live validation on a lab host

1. On a lab machine (preferably with Tamper Protection temporarily disabled to allow the write to succeed, though the attempt might log regardless), open PowerShell as Administrator.
2. Run `Add-MpPreference -ExclusionPath "C:\Temp"`
3. Run `Set-MpPreference -DisableRealtimeMonitoring $true`
4. Verify that `DeviceRegistryEvents` captures these changes and the query generates High severity alerts.
5. Restore the settings: `Remove-MpPreference -ExclusionPath "C:\Temp"` and `Set-MpPreference -DisableRealtimeMonitoring $false`

## Atomic Red Team

Relevant Atomics for T1562.001:
- **T1562.001 - Disable Windows Defender Real-Time Protection:** Uses PowerShell to disable protection.
- **T1562.001 - Add Windows Defender Exclusion:** Uses PowerShell to add a folder exclusion.
- **T1562.001 - Modify Registry to Disable Windows Defender:** Uses `reg.exe` to modify Defender registry keys.

These atomics directly exercise the registry keys targeted by this rule.

## Known limitations

- **Tamper Protection:** If Tamper Protection is enabled, it blocks these registry changes. Depending on the exact Windows version and EDR agent version, the blocked write attempt might not always be recorded in `DeviceRegistryEvents`.
- **WMI/PowerShell API:** If an adversary disables Defender using direct WMI calls or the Defender PowerShell module without touching the registry (if possible depending on the context), this registry-based rule might miss it. However, most PowerShell cmdlets (`Set-MpPreference`) translate to registry writes under the hood.
- **Other Security Products:** This rule is specific to Microsoft Defender. It does not detect tampering against third-party antivirus products.
