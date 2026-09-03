# Validation

## Unit test against fixtures

`tests/fixtures/t1110_failed_logon_burst.json` contains synthetic events representing sequences of logons, already aggregated to simulate the join condition.

| Fixture | Shape | Expected |
|---|---|---|
| `tp_high_volume_brute_force` | 25 failed logons followed by success from external IP | Fire, High (score 90) |
| `tp_medium_volume_spray` | 12 failed logons followed by success | Fire, Medium (score 70) |
| `tp_low_volume_guess` | 6 failed logons followed by success | Fire, Low (score 50) |
| `fp_below_threshold` | 3 failed logons followed by success | No fire |

Run: `python tools/run_tests.py T1110`

The scorer for this rule processes the aggregated output structure of the KQL query rather than raw `DeviceLogonEvents`, as testing the temporal join logic inside Python would simply duplicate the Kusto engine rather than validating the rule's scoring logic.

## Live validation on a lab host

1. On a lab machine or domain controller with auditing enabled, attempt to log in with an incorrect password 6 times in rapid succession.
2. Log in successfully with the correct password on the 7th attempt.
3. Wait for the events to populate in `DeviceLogonEvents`.
4. Run the query and verify a Medium severity alert is generated.
5. Repeat the test with 25 incorrect attempts to verify the High severity threshold.

## Atomic Red Team

Relevant Atomics for T1110:
- **T1110.001 - Password Guessing:** Simulates brute force against a specific account. If followed by a legitimate login, it will trigger this rule.
- **T1110.003 - Password Spraying:** If the script hits the same account multiple times (e.g. rotating through a password list) and eventually succeeds, the rule will fire.

## Known limitations

- **Distributed Brute Force:** If an attacker uses a botnet and spreads the failed attempts across hundreds of different `RemoteIP`s, the rule will miss it because the `join` explicitly correlates on `RemoteIP`.
- **Slow Spraying:** If the failures are spaced out over hours (exceeding the 15-minute `BurstWindow`), they won't be grouped together, allowing a "low and slow" attack to bypass the threshold.
- **Internal lateral movement:** If the attack originates from within the network where `RemoteIP` is not consistently logged for certain authentication protocols (like some Kerberos tickets), the join might fail.
