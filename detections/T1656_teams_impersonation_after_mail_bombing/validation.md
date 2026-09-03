# Validation

## Unit test against fixtures

`tests/fixtures/t1656_teams_impersonation.json` contains four correlated scenarios, each holding
a mail flood summary and an external chat event.

| Fixture | Shape | Expected |
|---|---|---|
| `tp_helpdesk_persona_20min` | 210 mails from 60 domains, then "IT Help Desk" external chat 20 minutes later | Fire, High (score 120) |
| `tp_real_name_persona_3h` | 90 mails from 30 domains, then external chat from a personal display name 3 hours later | Fire, Medium (score 60) |
| `fp_trusted_msp` | Flood, then chat from a tenant listed in `TrustedSupportTenants` | No fire |
| `fp_flood_no_contact` | Flood with no external chat inside the window | No fire |

Run: `python tools/run_tests.py T1656`

The second fixture matters more than the first. It is the operator who does not use an obvious
support persona, scores only Medium, and would be missed entirely by a rule that required the
persona keyword. It is included specifically to prove the correlation carries the detection.

## Live validation

This one cannot be safely exercised end to end, because doing so means mail bombing a real
mailbox and initiating federated contact. Validation is therefore in two independent halves.

**Stage 1, the flood detection.** Replay is not needed. Run the flood half of the query alone over
90 days of history with the threshold lowered to 20 messages and 10 domains. Every tenant has
some genuine bulk mail, so you will get hits, and confirming that the aggregation and windowing
behave as intended on real volumes is the point.

**Stage 2, the external chat detection.** Send a Teams message from a separate tenant you control
to a lab user, with a display name containing "IT Support". Confirm it surfaces in
`CloudAppEvents` with `CommunicationType` of `ExternalFederated` and that the parsing extracts the
sender UPN and display name correctly.

If both halves are confirmed independently, the join is arithmetic.

## Atomic Red Team

No atomic exists for this technique and one is not realistically constructible, since the attack
is entirely social and crosses two SaaS surfaces. Documented as a permanent validation gap rather
than an outstanding task.

## Known limitations

- `RawEventData` field names for Teams events are not stable across tenants and licensing tiers.
  The `CommunicationType` and `SenderUPN` extraction in this query should be confirmed against
  your own data before deployment. This is the most likely thing to be wrong on first run.
- Recipient extraction from `ParticipantInfo` is approximate for group chats. The rule is written
  for one to one contact, which is what this attack uses.
- An operator who compromises an account in a tenant you already trust bypasses the external
  federation condition entirely.
- If the mail bombing uses a single high volume sender rather than many services, the
  `DistinctSenderDomains` threshold suppresses it. That variant is better caught by an
  anti spam volume rule, which is a different control.
