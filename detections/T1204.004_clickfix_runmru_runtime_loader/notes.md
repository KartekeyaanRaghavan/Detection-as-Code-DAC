# ClickFix: command pasted into the Run dialog, and the runtime loader that follows

| | |
|---|---|
| **ATT&CK** | T1204.004 Malicious Copy and Paste, T1059.001, T1105, T1543.003 |
| **Tactic** | Execution, Command and Control, Persistence |
| **Data source** | `DeviceRegistryEvents`, `DeviceProcessEvents` (Defender for Endpoint) |
| **Status** | Query A validated against fixtures. Queries B and C documented, not yet fixture-tested |

## Hypothesis

ClickFix removes the exploit from the intrusion. A lure page claims something is broken, tells the
user to press Win+R and paste a supplied command, and the user executes it themselves. There is no
macro, no attachment and no vulnerability to detect, which is precisely why it works.

What survives is a registry artefact. Every command run through the Run dialog is written to
`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`. Users type `cmd`, `notepad`,
`\\fileserver` and drive letters there. They do not type base64 blobs, `curl -Lo`, or
`-ExecutionPolicy Bypass`. The gap between those two populations is the detection.

## Why this is the right anchor

Detecting further down the chain is possible but worse:

- The interpreter is `powershell.exe`, which is everywhere.
- The second stage is often a **legitimately signed runtime** such as `deno.exe`, `bun.exe` or
  `node.exe`, dropped deliberately because it is trusted, passes signature checks, and executes
  attacker script entirely in memory. Nothing malicious is ever written to disk in a form AV
  will recognise.
- The C2 leaves the host over ordinary HTTPS.

The RunMRU write happens once, early, and is almost noise-free. It is the cheapest place to catch
the whole family.

## Signal weighting in query A

| Signal | Weight | Rationale |
|---|---|---|
| Interpreter token present | 40 | `powershell`, `mshta`, `msiexec` in the Run box |
| Downloader token present | 30 | `curl`, `certutil`, a URL |
| Obfuscation token present | 40 | `-enc`, `IEX`, hidden window, bypass |
| Interpreter **and** downloader together | 20 | Either alone is arguable; together is the ClickFix shape |
| Command longer than 120 characters | 20 | Humans do not type this much into Run |
| Embedded base64 blob (regex) | 30 | Strongest single indicator |

## False positives, and the honest problem with this rule

1. **Admins and developers.** They do paste real commands into Run. Volume is low and clears fast
   by account. Exclude named admin accounts, not the pattern.
2. **Vendor documentation that says "paste this msiexec command".** Legitimate software genuinely
   ships install instructions in this shape.
3. **Helpdesk walking a user through a fix over the phone.**

Number three is the one worth being honest about. **ClickFix works by impersonating legitimate IT
support, so the benign behaviour and the malicious behaviour are behaviourally identical at the
host.** No amount of rule tuning separates them. What separates them is context the host does not
have: was there a ticket, did the user visit a lure page in the minutes prior, is the destination
domain newly registered.

The correct response is to accept a modest FP rate here and resolve it in triage, rather than to
tune the rule until it stops firing. A ClickFix detection with zero false positives has almost
certainly been tuned into uselessness.

## Triage steps

1. Read the pasted command in full. It usually decodes to the whole first stage.
2. Pull the user's browser history for the 10 minutes before the paste. The lure page is the
   confirming evidence and gives you the campaign infrastructure.
3. Check whether a second stage executed (query B) and whether anything now listens on localhost.
   In-memory loaders frequently open a local socket for their C2 relay.
4. Check for persistence: service creation, scheduled task, Run key, startup folder.
5. Decode and resolve every domain in the command. Check registration age.
6. If the second stage ran, treat the host as compromised. Signed-runtime loaders leave very
   little for AV to find, so a clean scan is not clearance.

## Response playbook

1. Isolate the device. If a second stage executed, do this before user contact.
2. Collect the pasted command, the lure URL, the second-stage binary path and hash, and any
   listening sockets, before remediation destroys them.
3. Block the lure and C2 domains at the proxy and in network protection.
4. Kill the runtime process, remove the dropped runtime and script, remove persistence.
5. Reset the user's credentials and revoke sessions. Infostealers are a common ClickFix payload
   and browser cookie theft is the usual objective.
6. Hunt the lure domain and the pasted command shape across the estate. ClickFix campaigns are
   sprayed, so one hit rarely means one victim.
7. Feed the lure domain to the mail and web filtering teams.

## User-facing follow-up

This one is worth stating because it is a control, not a nicety: ClickFix is defeated by users
knowing that no legitimate support process asks them to paste a command into Win+R. That belongs
in awareness training as a specific, concrete instruction rather than general phishing advice.

## Deployment notes

- Query A as a Defender custom detection at 1 hour, or a Sentinel scheduled rule at the same.
- Run query D first. RunMRU telemetry depends on registry collection being enabled; a silent rule
  and a clean estate look identical from the console.
- Expected volume in a mid-size estate: a handful per month at Medium and above.
