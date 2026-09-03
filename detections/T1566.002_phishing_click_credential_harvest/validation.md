# Validation

## Unit test against fixtures

`tests/fixtures/t1566_002_phishing_click.json` contains five joined click and mail records.

| Fixture | Shape | Expected |
|---|---|---|
| `tp_unknown_sender_auth_url_fast_click` | Unknown sender, delivered, URL contains `login`, clicked in 4 minutes | Fire, High (score 100) |
| `tp_unknown_sender_auth_url_slow` | Unknown sender, junked but retrieved, auth URL, clicked after 2 days | Fire, Medium (score 70) |
| `tp_unknown_sender_generic_url` | Unknown sender, junked, URL with no auth keywords | Fire, Low (score 40) |
| `fp_known_vendor_domain` | Sender with 40 prior mails in the prevalence window | No fire |
| `fp_simulation_sender` | Sender listed in `SimulationSenders` | No fire |

Run: `python tools/run_tests.py T1566`

The third fixture is the honest one. It is a real false positive shape scoring Low, and it is
included to show what the bottom of this rule's output actually looks like rather than only
demonstrating the cases that work.

## Live validation in a lab tenant

Requires a Microsoft 365 tenant with Safe Links enabled and a second domain you control.

1. Confirm telemetry first. If `UrlClickEvents` has no rows in the last 7 days, Safe Links is
   not enabled or not licensed, and this rule cannot fire. Verify before anything else.
2. From an unrelated domain with no prior mail history to the tenant, send a lab user a message
   containing a link to a benign page whose path contains `login`, for example
   `https://<your-lab-domain>/login/test`. Do not build or host a credential form.
3. Click the link as the lab user.
4. Confirm the hit within 30 to 60 minutes, and that `LandsOnAuthPage` is true and the join on
   `NetworkMessageId` resolved the sender correctly.
5. Confirm the prevalence logic by repeating from a domain that has previously sent the tenant
   more than `PrevalenceFloor` messages. It should not fire.

Step 5 is the one people skip and it is the one that matters, since a broken prevalence join
produces a rule that fires on everything and looks like it is working.

## Atomic Red Team

Not applicable. `T1566.002` is a delivery technique executed from the attacker's infrastructure,
so there is nothing to execute on a host. Validation is the lab tenant procedure above.

## Known limitations

- Depends entirely on Safe Links. No Safe Links, no `UrlClickEvents`, no detection.
- The `NetworkMessageId` join fails for links clicked from Teams messages rather than mail, so
  Teams delivered phishing is only partially covered.
- Prevalence is computed at the domain level. An operator who compromises a mailbox at a supplier
  the organisation corresponds with regularly bypasses the prevalence check entirely, and that is
  the highest impact blind spot in this rule.
- The authentication keyword list matches on the URL string only. A harvesting page on a path
  with no telling keywords scores 15 points lower and may land at Low.
- No detection of the credential submission itself, which is not visible in this telemetry.
