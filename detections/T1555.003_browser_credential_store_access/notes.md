# Browser credential store copied out of its profile directory

| | |
|---|---|
| **ATT&CK** | T1555.003 Credentials from Web Browsers |
| **Tactic** | Credential Access |
| **Data source** | `DeviceFileEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents` |
| **Status** | Validated against fixtures |

## Context

An infostealer does not exploit the browser. It copies the browser's files. If a file bearing the
name of a credential store appears anywhere other than a browser profile directory, something
moved it, and the set of legitimate reasons to move it is small and enumerable.

## Why the copy and not the read

This is the constraint that shaped the whole rule, so it is worth stating before the logic.

**Defender for Endpoint does not emit a general file read event.** `DeviceFileEvents` is
documented as file creation, modification and rename. There is no `FileRead`. A rule written
against the intuitive behaviour - "alert when a non browser process reads Login Data" - has no
telemetry underneath it and would never fire, however good it looks in a repository.

What makes the rule viable is a quirk of Chromium: it holds a lock on `Login Data` while the
browser is running. A stealer that tries to read in place fails on any machine where the user
has a browser open, which is most of them. So the working technique, and the one used by every
commodity family worth naming, is to copy the store to a temporary location and read the copy.
That copy is a creation event.

The anchor is therefore the file arriving somewhere it does not belong:

| Benign | Theft |
|---|---|
| `Login Data` inside `\User Data\Default\` | `Login Data` inside `\AppData\Local\Temp\` |
| One store, one vendor, one file | Four stores, two vendors, one burst |
| The store, but never `Local State` | `Local State` or `key4.db` taken alongside |
| A signed agent in Program Files | An unsigned binary in a user writable path |

The third row carries more weight than its size suggests. `Login Data` on its own is DPAPI
encrypted and close to worthless. `Local State` holds the wrapped AES key. A tool that takes
both is decrypting, not backing up.

## Risk Scoring

`Local State` or `key4.db` alongside the store is worth 30, because it separates theft from
copying. Three or more distinct stores in one window is worth 25, because a sweep is a program
enumerating what is installed rather than a user importing one thing. Touching both a Chromium
store and a Gecko store is worth 20 on its own: no legitimate tool needs both, but every stealer
takes both, because it does not know in advance what the victim uses.

The copier wearing a browser's name while not living in a browser's directory is worth 30. That
is the same reasoning as the T1219 rule - judge the execution by its path, not its name.

## Known False Positives, ranked by how often they occur

1. **Backup and profile roaming agents.** By far the largest source of volume. They copy whole
   profile trees, so they trip the sweep and multi vendor signals at once and score High. This is
   the reason `AllowedCopiers` exists and the reason the baseline query is not optional.
2. **Password manager import wizards.** They copy exactly these files, on purpose, once. They
   score Low because they take one store, stay signed, and run from Program Files. Working as
   intended: visible, deprioritised, not suppressed.
3. **Browser migration during onboarding.** Provisioning scripts move whole profiles between
   machines. Bursty, correlated with a start date, and clears on the account.
4. **DLP and endpoint security products inventorying browser data.** Allow list by name and
   signing certificate, never by path alone.
5. **Your own IR tooling.** Suppress by the analyst account, not by the binary, so that an
   operator running the same tool still alerts.

## How to Triage

1. Read `StoresTaken` first. Whether `Local State` or `key4.db` is in the set decides whether you
   are looking at theft or at housekeeping.
2. Identify the copier. `CopierPath`, `CopierSigner` and `CopierCommand` usually settle it in one
   look. An unsigned binary in `\AppData\Local\Temp` needs no further argument.
3. Run the second anchor query. If the copier came in through a LOLBin, there is a parent process
   and a command line that names the source.
4. Run the enrichment query. A copy followed by an archive write and an outbound connection from
   the same process within minutes is the complete technique and closes the case.
5. Establish delivery. Stealers arrive by ClickFix paste, cracked software, or a malicious ad.
   Check `DeviceRegistryEvents` for a RunMRU write - the T1204.004 rule in this repository covers
   that path and the two frequently fire on the same host within the same hour.
6. Determine which browsers the user was signed into. That, not the file list, is the blast radius.

## Playbook

1. Isolate the device.
2. Assume every credential and every session cookie in the affected profiles is compromised. The
   copy has already left; containment does not undo it.
3. Revoke sessions before resetting passwords. A stolen session cookie survives a password change,
   which is the single most common gap in the response to this technique. In Entra ID that is a
   revoke of refresh tokens, not just a reset.
4. Reset credentials for every site the user had saved, prioritising anything reachable from the
   corporate identity.
5. Re register MFA if any authenticator secret was stored in the browser.
6. Watch for the consequence rather than the cause: an adversary in the middle sign in and a
   mailbox rule. The T1114.003 rule here is the other half of this intrusion and should be checked
   for the same user for at least thirty days.
7. Hunt the copier hash and the landing directory estate wide.
8. Preserve the archive if one was written. It is an exact inventory of what the operator has.

## Deployment notes

- Run the baseline query first and allow list what you find. Backup agents will otherwise produce
  an unusable day one volume, and they score High, so they will not be quietly ignorable.
- Schedule at 1 hour. Exfiltration follows the copy within minutes, so this is a rule where
  detection latency translates directly into how much of the response is still useful.
- The `sweepWindow` of 5 minutes is generous. Stealers finish in seconds; the window is sized for
  the backup agents you are trying to characterise, not for the threat.
