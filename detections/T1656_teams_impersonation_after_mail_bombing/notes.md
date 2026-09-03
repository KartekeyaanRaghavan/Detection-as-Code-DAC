# External Teams contact to a user who was just mail bombed

| | |
|---|---|
| **ATT&CK** | T1656 Impersonation, T1585.002, leading to T1219 |
| **Tactic** | Initial Access, Resource Development |
| **Data source** | `EmailEvents`, `CloudAppEvents` |
| **Status** | Validated against fixtures |

## Hypothesis

The operator signs the victim's address up to hundreds of mailing lists and registration forms.
Within an hour the mailbox is unusable. Then an external Teams account appears, presenting itself
as the internal help desk, offering to fix the mail problem, and asking the victim to start a
remote session. The remote session is the actual objective.

## Why the correlation is the detection

Take either half alone and it does not work:

| Signal alone | Why it fails |
|---|---|
| Mail bombing | Looks like a user who signed up for too many newsletters. Also used as cover for a single real notification, so it is noisy in both directions |
| External Teams contact | Entirely normal in any tenant that permits federation |

Together, in a short window, they are close to unambiguous. The operator has a timing constraint:
the lure only works while the victim is still looking at a flooded mailbox, so the second stage
arrives within minutes to hours. That constraint is a gift, because it lets the rule use a tight
correlation window and stay precise.

This is worth understanding as a general principle. Some techniques have no high fidelity single
indicator, and the answer is not a lower threshold on a weak signal but a correlation across two
data sources that the attacker's own operational needs force to be close together in time.

## Signal weighting

| Signal | Weight |
|---|---|
| The correlation itself, flood then external contact in window | 60 |
| Sender display name impersonates support or security | 30 |
| Contact arrives within 60 minutes of the flood ending | 20 |
| Flood exceeds 150 messages | 10 |

The correlation carries most of the score deliberately. The persona check is a bonus, not a
requirement, because an operator who names themselves after a real internal colleague rather than
"IT Support" is more dangerous, not less, and must still fire.

## False positives

1. **Genuine federated support from an MSP or outsourced help desk.** The real one. Allow list by
   sending tenant in `TrustedSupportTenants`, never by display name, since display name is the
   thing being forged.
2. **Vendor support staff** whose display name legitimately contains "support", contacting a user
   who separately happens to be receiving a lot of mail. Rare, and clears on inspection.
3. **A user who genuinely subscribed to many services** in one sitting and separately received an
   external message. The 8 hour window and the sender domain count make this uncommon.

Notably absent from this list: high volume noise. This rule should fire a handful of times a year
in a mid size tenant. If it fires daily, the thresholds are wrong for your environment, or you
have a campaign.

## Triage steps

1. Read the actual Teams messages. Social engineering is legible in a way that most telemetry
   is not, and the transcript usually settles the verdict immediately.
2. Check the sending tenant. Operator tenants are typically days or weeks old, have one user, and
   have contacted several of your users rather than one.
3. Pivot to every other recipient that tenant has messaged. This is almost always a campaign
   against multiple users, and the others may not have been mail bombed yet.
4. Run the follow on query. If remote access software executed on the victim's device in the
   hours after the chat, this is no longer attempted social engineering, it is an active
   intrusion and the T1219 playbook applies immediately.
5. Check whether the victim entered credentials or approved an MFA prompt during the window.

## Response playbook

1. If remote access ran, isolate the device first and work the T1219 playbook. Everything below
   is secondary to that.
2. Block the external tenant in Teams external access settings.
3. Preserve the chat transcript before it is deleted. Operators delete their side.
4. Contact the victim by phone, not by Teams or mail. Both channels are compromised in the
   attacker's favour at this moment, and the mailbox is unusable anyway.
5. Reset credentials and revoke sessions if there is any indication of credential entry.
6. Identify every other user the tenant contacted and warn them the same day.
7. Send a short tenant wide notice. This attack propagates by people believing a plausible help
   desk, so telling users that the help desk will never contact them cold over federated Teams
   is a genuine control, not a formality.

## Deployment notes

- Requires both `EmailEvents` and `CloudAppEvents`. If Teams audit is not flowing into Defender,
  this rule is silent, not clean.
- Consider restricting Teams external access to allow listed domains. If your organisation does
  that, this rule becomes a detection for a control failure, which is still worth having.
- Schedule at 1 hour. Detection latency matters here because the remote session happens fast.
