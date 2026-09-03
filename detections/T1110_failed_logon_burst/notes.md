# Failed logon burst followed by success

| | |
|---|---|
| **ATT&CK** | T1110 Brute Force |
| **Tactic** | Credential Access |
| **Data source** | `DeviceLogonEvents` |
| **Status** | Validated against fixtures |

## Hypothesis

Adversaries often attempt to brute-force or password-spray accounts to gain initial access or escalate privileges. A defining characteristic of a successful brute-force or spray attack is a sequence of failed logon attempts culminating in a successful logon for the same account from the same source.

## Signal weighting

The rule inherently carries a medium-to-high severity because a burst of failures *followed by a success* means the account is now actively compromised (or a user finally remembered their password). The score escalates based on the volume of failed attempts prior to the success:

- **Baseline score (50):** Meeting the minimum threshold (default 5 failures within 15 minutes) implies a successful guess or a user struggling with a password.
- **High volume (+20 / +40):** The more failures that precede the success, the less likely it is to be a human typing errors, and the more likely it is an automated attack. 10+ failures adds 20, 20+ failures adds another 20.

## False positives, ranked by how often they occur

1. **Users forgetting their passwords:** Legitimate users trying multiple passwords before finally getting it right or resetting it. Usually characterised by a small burst (e.g. 5-7 attempts).
2. **Stale credentials in automated scripts/services:** A scheduled task or service using an old password might fail repeatedly, and a subsequent manual login by the administrator to fix it might trigger the rule.
3. **Misconfigured applications:** Apps with aggressive retry logic using cached (invalid) credentials, followed by a user manually updating the credentials.

## Triage steps

1. Check the `FailedCount`. A count of 6 is likely a user. A count of 200 is an attack.
2. Investigate the `RemoteIP`. Is it a known corporate IP, a known VPN exit node, or an unfamiliar external IP?
3. Review post-logon activity for the `Account` on the `DeviceName`. Look for unusual process executions, scheduled tasks, or further lateral movement attempts.
4. Contact the user to confirm if they were locked out or had trouble signing in at the time of the event.

## Response playbook

1. If the `RemoteIP` is suspicious and the `FailedCount` is high, assume the account is compromised.
2. Immediately force a password reset for the affected `Account` and revoke all active session tokens.
3. Isolate the affected `DeviceName` if it is an internal asset.
4. Block the `RemoteIP` at the network perimeter.
5. Review all actions performed by the `Account` after the `SuccessTime`.

## Deployment notes

- **Tuning thresholds:** The `BurstThreshold` and `BurstWindow` must be tuned to your environment's baseline. A threshold of 5 might be too noisy if users frequently lock themselves out.
- The rule looks for failures and successes from the same `RemoteIP` and `AccountName` to correlate the attack with the successful breach.
