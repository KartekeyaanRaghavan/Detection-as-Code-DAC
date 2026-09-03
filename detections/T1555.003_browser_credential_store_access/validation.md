# Validation

## Unit test against fixtures

`tests/fixtures/t1555_003_browser_credential_store.json` contains five synthetic per process,
per window aggregates, matching the `summarize` in `detection.kql` rather than raw file events.

| Fixture | Shape | Expected |
|---|---|---|
| `tp_stealer_full_sweep_both_vendors` | Unsigned `svchost.exe` in Temp takes 4 stores across Chromium and Gecko, including `Local State` | Fire, High (score 170) |
| `tp_chromium_only_masquerading_copier` | Unsigned `chrome.exe` in AppData\Roaming takes 3 Chromium stores including `Local State` | Fire, High (score 180) |
| `tp_single_store_plus_master_key` | Signed `rundll32.exe` takes `Login Data` and `Local State` into Temp | Fire, Medium (score 80) |
| `fp_backup_agent_allowlisted` | Veeam profile agent copies 4 stores to a backup volume | No fire, allow listed |
| `fp_password_manager_import_signed` | Signed 1Password takes one store into its own import directory | Fire, Low (score 50) |

Run: `python tools/run_tests.py T1555`

The second fixture scores higher than the first despite taking fewer stores, because a process
called `chrome.exe` that is not in a Chrome directory is a stronger statement than a process
called `svchost.exe` that is not in System32. That is intentional, and it is the same reasoning
the T1219 rule uses.

The last fixture is not suppressed. A password manager import is a real false positive, but it
scores Low and sorts to the bottom, which is the correct treatment for something a rule cannot
distinguish from the real thing without knowing whether a user was sitting at the keyboard.

## Live validation on a lab host

1. Run the baseline query in the KQL file first and record which processes already move these
   files in your estate.
2. On an isolated lab VM with Chrome and Firefox both installed and signed into throwaway
   accounts, open a browser so the lock on `Login Data` is held.
3. Copy the stores out with a plain shell, which is what a stealer does:
   `copy "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" %TEMP%\ld.tmp` -
   note this lands under a different name and is the case the primary query misses.
4. Repeat preserving the file name, into `%TEMP%\Login Data`, and confirm the primary query
   fires within 15 to 30 minutes.
5. Confirm `TakesMasterKey` is true once `Local State` is included, and that `MultiVendor`
   flips to true once a Firefox store is added.
6. Run the second anchor query and confirm the step 3 copy is caught there by command line.

## Atomic Red Team

`T1555.003` atomics cover the Chromium and Firefox stores and mostly copy with the file name
preserved, so they exercise the primary query well. The relevant tests copy `Login Data` and
`logins.json` to a staging directory. They do not take `Local State`, so the master key signal
stays false and the scores land Medium rather than High - useful as a partial check, and a fair
illustration of why that signal is weighted the way it is.

## Known limitations

- **A copy to a renamed destination is missed by the primary query.** This is the largest gap.
  `copy "Login Data" %TEMP%\x.tmp` produces a creation event for `x.tmp`, which matches nothing.
  The second anchor query catches it by command line when a LOLBin was used, but a compiled
  stealer that copies through the API leaves neither. Closing this properly needs file content
  or hash based identification, which this table does not offer.
- **Reading in place is invisible.** Defender emits no file read event. A stealer that waits for
  the browser to close and reads the store directly produces no telemetry at all under this rule.
- **DPAPI decryption itself is not covered.** The rule detects the theft of the material, not the
  unwrapping of it.
- **Browsers outside the listed profile directory conventions** - portable builds, unusual
  installs, Chromium forks not enumerated in `ProfileDirs` - will produce false positives on
  every ordinary write, because their own stores look like copies. Add them to `ProfileDirs`.
- **Cookies specifically.** The Chromium cookie database moved under `\Network\` and is simply
  named `Cookies`, which is a common enough file name that including it in the primary match
  produced unacceptable noise in design. It is deliberately excluded from `ChromiumFiles` and is
  covered only by the second anchor query.
- The aggregation window means a stealer that paces its copies more than 5 minutes apart is
  scored as several separate low scoring events rather than one sweep.
