# Validation

## Unit test against fixtures

`tests/fixtures/t1219_rmm.json` contains five synthetic `DeviceProcessEvents` records.

| Fixture | Shape | Expected |
|---|---|---|
| `tp_screenconnect_appdata_from_browser` | ScreenConnect client in AppData, parent `msedge.exe`, no signer | Fire, High (score 110) |
| `tp_anydesk_downloads_powershell` | AnyDesk in Downloads, parent `powershell.exe` | Fire, High (score 90) |
| `tp_rustdesk_public_unsigned` | RustDesk in Users\Public, parent `explorer.exe`, unsigned | Fire, High (score 110) |
| `fp_teamviewer_program_files` | TeamViewer under Program Files, parent a service | No fire |
| `fp_anydesk_dev_downloads` | AnyDesk in Downloads launched by explorer, signed | Fire, High (score 90), cleared in triage by account |

Run: `python tools/run_tests.py T1219`

The last fixture is deliberately not suppressed by the rule. It is a real false positive that the
logic cannot separate from the true positives, and pretending otherwise by adding an exclusion
would weaken the detection. It is resolved by an analyst in under a minute.

## Live validation on a lab host

1. Run the baseline query in the KQL file first. Record what RMM already exists in the estate.
2. Download a portable AnyDesk build to `%USERPROFILE%\Downloads` on an isolated lab VM and
   launch it from PowerShell. Do not connect it to anything.
3. Confirm the hit within 15 to 30 minutes, and that `FromUserWritable` and `DeliveryParent`
   are both true.
4. Run the network enrichment query and confirm the relay endpoints appear.

## Atomic Red Team

`T1219` atomics exist and cover several of these binaries. They install rather than side load, so
they exercise the process name condition but not the user writable path condition. Useful as a
partial check, not as full validation.

## Known limitations

- Renamed RMM binaries are missed. The rule matches on file name. Extending it to match on the
  original file name field or signing certificate would close this and is the obvious next
  iteration.
- RMM delivered as an MSI and installed to Program Files by an operator with local admin will
  not trip the path condition, and only trips the parent condition if `msiexec.exe` was launched
  by a script host.
- Browser based remote access, where no binary is dropped at all, is a different technique and
  is not covered here.
- The unsigned check uses the company name field being empty, which is a weak proxy. Proper
  signature verification is not available in this table.
