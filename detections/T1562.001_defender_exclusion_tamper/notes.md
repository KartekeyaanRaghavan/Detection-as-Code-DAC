# Defender exclusion added or tamper protection disabled

| | |
|---|---|
| **ATT&CK** | T1562.001 Impair Defenses: Disable or Modify Tools |
| **Tactic** | Defense Evasion |
| **Data source** | `DeviceRegistryEvents` |
| **Status** | Validated against fixtures |

## Hypothesis

Before executing malicious payloads, adversaries often attempt to blind endpoint security tools. For Windows Defender, this frequently involves writing to specific registry keys to disable Real-Time Protection, disable Behavior Monitoring, disable Tamper Protection, or add path exclusions. Any non-system process making these modifications is highly suspicious.

## Signal weighting

Modifying core Defender settings inherently warrants a Medium to High score. The risk score escalates based on the context of the modification:

- **Baseline score (60):** Any untrusted process modifying these keys.
- **Tampering vs Exclusions (+20):** Attempting to disable core features (like Tamper Protection or Real-Time Monitoring) is generally more suspicious than adding an exclusion, as exclusions are often added manually by developers.
- **Suspicious actor (+30):** Modifications performed via living-off-the-land binaries (LOLBins) like `powershell.exe`, `cmd.exe`, or `reg.exe` strongly correlate with script-based deployment or hands-on-keyboard activity.
- **User-writable / Unsigned (+30 / +20):** Modifications initiated by unsigned payloads running from `Temp` or `Downloads` are definitively malicious.

## False positives, ranked by how often they occur

1. **Enterprise management tools (Intune, SCCM, GPO):** These are the authorized mechanisms for configuring Defender across the estate and will frequently write to these keys. They should be allowlisted in the baseline phase.
2. **Software installers:** Some aggressive legitimate software installers may attempt to add their own installation directories to Defender's exclusion list.
3. **Developers/IT Helpdesk:** Manual troubleshooting or development activity where users temporarily disable protection or add folder exclusions.

## Triage steps

1. Examine the `RegistryKey` and `RegistryValueData`. Is this a broad exclusion (e.g., `C:\`) or a specific application folder? Is it disabling Real-Time Protection?
2. Identify the `Actor`. Is it a known management tool or an unexpected process (e.g., `powershell.exe`, an unsigned binary)?
3. Look at the `CommandLine`. `Add-MpPreference -ExclusionPath` or `reg add` commands are typical evasion techniques.
4. Investigate activity occurring immediately *after* the modification on the same device. Disabling defenses is usually the precursor to payload execution or lateral movement.

## Response playbook

1. Revert the unauthorized registry change. Defender's Tamper Protection, if active, may have blocked the actual change, but the attempt itself is still logged.
2. Isolate the endpoint if the modification was initiated by an untrusted or suspicious process.
3. Identify and analyze the payload that the adversary intended to run after blinding Defender.
4. Review the timeline of events leading up to the registry modification to determine the initial access vector.

## Deployment notes

- **Tamper Protection effectiveness:** If Tamper Protection is enabled in your tenant, many of these registry writes will be blocked by the OS. However, `DeviceRegistryEvents` often logs the *attempted* write before it is blocked, making this detection valuable as an early warning signal even if the evasion fails.
- **Tuning:** Ensure that legitimate deployment mechanisms (like `poqexec.exe` or `svchost.exe` hosting the Group Policy Client) are in `AllowedModifiers`.
