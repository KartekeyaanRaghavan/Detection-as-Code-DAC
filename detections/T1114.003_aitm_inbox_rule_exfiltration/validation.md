# Validation

## Unit test against fixtures

`tests/fixtures/t1114_003_inbox_rule.json` contains six synthetic `CloudAppEvents` records:
three that must fire and three that must not.

| Fixture | Shape | Expected |
|---|---|---|
| `tp_forward_external_hide` | Forwards to an external address, moves to RSS Feeds, marks read, keywords include `invoice`, rule named `.` | Fire, High (score 125) |
| `tp_forward_external_only` | Forwards to an external address, no suppression | Fire, Medium (score 50) |
| `tp_hide_only_named_dot` | No forward, moves to Deleted Items, rule named `.` | Fire, Medium (score 45) |
| `fp_internal_delegate` | Forwards to an in-tenant delegate | No fire |
| `fp_user_newsletter_archive` | Moves newsletters to Archive, no forward, named rule | Fire at Low only (score 30) |
| `fp_migration_tooling` | Bulk rule creation by a service principal | Fire, suppressed by actor exclusion |

Run: `python tools/run_tests.py detections/T1114.003_aitm_inbox_rule_exfiltration`

## Live validation in a lab tenant

Requires a Microsoft 365 developer tenant. Do not run against a production tenant.

1. Create a test user and a second "external" mailbox on an unrelated domain.
2. As the test user, create the rule through EWS or Graph so the audit record carries a full
   `Parameters` array:

   ```powershell
   New-InboxRule -Mailbox testuser@lab.example `
     -Name "." `
     -SubjectOrBodyContainsWords "invoice","payment" `
     -ForwardTo "collector@external.example" `
     -MoveToFolder "RSS Feeds" `
     -MarkAsRead $true `
     -StopProcessingRules $true
   ```

3. Mailbox audit records surface in `CloudAppEvents` with a lag of roughly 30 to 90 minutes.
   Do not conclude the rule failed inside that window.
4. Confirm the hit scores 125 and reports `ForwardsExternally = true`,
   `SuppressesMail = true`, `TargetsHighRiskKeywords = true`.

## Atomic Red Team

No current atomic covers Exchange Online mailbox rule creation. The closest on-host analogue is
`T1114.001` local mail collection, which exercises a different data source and does **not**
validate this rule. Treated as a coverage gap rather than papered over: see the gap list in the
repository README.

## Known limitations

- Rules created directly through the Graph API `mailFolders/inbox/messageRules` endpoint produce
  an audit record with a different parameter shape. Not yet covered.
- Transport rules at the organisation level are a separate technique and a separate detection.
- If mailbox auditing is disabled for a mailbox, no record is generated and this rule is blind.
  Verify `AuditEnabled` coverage before relying on it.
