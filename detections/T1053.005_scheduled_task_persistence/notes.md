# Scheduled task persistence via schtasks.exe

| | |
|---|---|
| **ATT&CK** | T1053.005 Scheduled Task/Job: Scheduled Task |
| **Tactic** | Persistence, Privilege Escalation |
| **Data source** | `DeviceProcessEvents` |
| **Status** | Validated against fixtures |

## Hypothesis

Adversaries use Windows Scheduled Tasks to establish persistence, execute payloads upon reboot, or execute payloads under the `SYSTEM` context. While scheduled tasks are created constantly by legitimate software, malicious tasks often involve executing LOLBins, downloading payloads, or originating from unsigned binaries in user-writable paths.

## Signal weighting

The baseline creation of a scheduled task by an unrecognised parent is a Low-to-Medium risk event (score 40). The score escalates based on how the task is configured and who is creating it:

- **Suspicious command line (+40):** A scheduled task executing `powershell.exe`, `cmd.exe`, or calling out to a URL (`http://`) is highly characteristic of malware staging.
- **User-writable path (+30):** A task created by an executable dropped into `\AppData\Local\Temp\` or `\Downloads\` strongly implies an unauthorized payload.
- **Unsigned parent (+20):** Most legitimate task creators (like updaters) are signed by the vendor.

## False positives, ranked by how often they occur

1. **Software Updaters:** Browsers, IDEs, and other software frequently install scheduled tasks to check for updates. The parent process (e.g. `googleupdate.exe`) is usually signed and should be allowlisted.
2. **Endpoint management scripts:** IT administrators may push scripts via Intune or SCCM that create temporary scheduled tasks to perform maintenance.
3. **Third-party software installers:** Installers (`msiexec.exe`) might configure background jobs.

## Triage steps

1. Examine the `CommandLine` to determine what the task actually runs (`/tr` flag in `schtasks`). Is it launching a script, an unsigned executable, or a known living-off-the-land binary?
2. Analyze the `Actor` (the process that ran `schtasks.exe`). Where did it execute from? Is it signed?
3. Determine the user context of the task (the `/ru` flag). Tasks configured to run as `SYSTEM` pose a higher risk.
4. Review process lineage. What launched the `Actor`? If the task was created by a macro in a Word document, it is definitively malicious.

## Response playbook

1. Immediately disable or delete the scheduled task to prevent execution.
2. Isolate the device if the task points to a malicious payload or script.
3. Retrieve and analyze the file referenced by the `/tr` parameter.
4. Hunt across the environment for the payload hash or the specific task name used by the adversary.

## Deployment notes

- **Baseline first:** Scheduled tasks are incredibly common. Review the baseline query to identify and allowlist the signed updaters and deployment tools used in your environment before enabling this rule.
- This rule specifically monitors the command-line usage of `schtasks.exe`. It does not detect tasks created via the COM API (e.g. using PowerShell's `Register-ScheduledTask` or C# implementations), which require monitoring `DeviceRegistryEvents` for changes to the `Schedule\TaskCache` keys or ETW providers.
