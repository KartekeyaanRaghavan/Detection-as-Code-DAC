# Remote monitoring and management tool executed from a user writable path

| | |
|---|---|
| **ATT&CK** | T1219 Remote Access Software |
| **Tactic** | Command and Control, Initial Access |
| **Data source** | `DeviceProcessEvents`, `DeviceNetworkEvents` |
| **Status** | Validated against fixtures |

## What are we looking for?

An operator who has social engineered a user into granting remote access will use commodity RMM
software rather than custom malware, because it is signed, often already allow listed, and
indistinguishable from IT activity at the process level. If the RMM binary runs from a user
profile directory, or is launched by a browser, mail client or script host, it was delivered
rather than deployed.

## Why path and parentage rather than the binary name

The binaries are legitimate. Blocking ScreenConnect outright breaks the IT team, and alerting on
its name alone produces noise proportional to how much your organisation uses it. What is
anomalous is the *shape* of the execution:

| Sanctioned deployment | Operator delivery |
|---|---|
| Installs under Program Files | Runs from AppData, Downloads, ProgramData |
| Launched by a management agent or service | Launched by a browser, Outlook, PowerShell, msiexec |
| Points at your organisation's relay | Points at an instance you do not own |
| Present across many machines, consistently | Appears on one machine, once |

The last row is why the baseline query at the bottom of the KQL matters more than the rule.

## Expected FPs, ranked by how often they occur

1. **Your own sanctioned RMM.** Unavoidable and expected. Handle it by naming the tool in
   `SanctionedRmm` and its install path in `SanctionedPaths`. Do not handle it by deleting the
   rule for that binary, because an operator using the same tool you deploy is a real scenario
   and a path check still catches it.
2. **Managed service providers.** Allow list on binary path plus signing certificate, never on
   process name alone.
3. **Portable or evaluation copies run by developers and IT staff from Downloads.** These score
   Medium and clear quickly by account.
4. **A user self installing remote access to reach their home machine.** Not an intrusion, but a
   policy violation worth a conversation, so resolve it rather than suppressing it.

## Investigation Steps

1. Establish where the binary came from. Check `DeviceFileEvents` for the download and the
   referring process.
2. Pull the network enrichment query. The relay endpoint usually settles the question in one
   look: an instance your organisation does not own is conclusive.
3. Check the signing information. Operator supplied ScreenConnect builds are frequently signed
   with the attacker's own trial tenant, which is visible in the company name field.
4. Look for the lure. Mail, a Teams message, a phone call to the user, or a ClickFix style paste.
   RMM delivery is almost always preceded by social engineering, not by an exploit.
5. Determine what happened during the session: files transferred, credentials accessed, other
   hosts reached.

## Containment & Response

1. Isolate the device.
2. Kill the RMM process and its service before the operator notices, if a session is live.
3. Preserve the client configuration file. It contains the relay address and is the best
   indicator to hunt with across the estate.
4. Block the relay domain and IP at the perimeter.
5. Remove the binary, its service registration and any persistence.
6. Reset the user's credentials. Assume anything visible on screen during the session is known
   to the operator.
7. Hunt the relay address and the binary hash estate wide. RMM delivery campaigns target many
   users in one organisation.
8. If the lure came by phone or Teams, warn the wider user population that day. This class of
   intrusion spreads through people, not through the network.

## Deployment notes

- Run the baseline query first and allow list what you find. Deploying blind produces an
  unusable day one volume.
- Schedule at 1 hour. RMM sessions are interactive, so detection latency matters more here than
  for persistence style detections.
