# Mailbox rule created to forward or hide mail after account compromise

| | |
|---|---|
| **ATT&CK** | T1114.003 Email Forwarding Rule, T1564.008 Email Hiding Rules |
| **Tactic** | Collection, Defense Evasion, Persistence |
| **Data source** | Exchange Online mailbox audit via `CloudAppEvents` (Defender XDR) or `OfficeActivity` (Sentinel) |
| **Status** | Validated against synthetic events, see `validation.md` |

## What are we looking for?

An operator who has stolen a session token through AiTM phishing will, within minutes to hours,
create a mailbox rule that (a) copies future correspondence out of the tenant, and (b) hides the
replies that would expose the compromise. Detecting the rule catches the intrusion at the point
where it becomes durable, and before the fraudulent invoice goes out.

## Why this rule rather than "risky sign-in"

The instinct is to detect the compromise at authentication. In AiTM that often does not work.
The operator replays a stolen session cookie against a session the tenant has already accepted,
so identity protection may score it as normal. The mailbox rule is a **behavioural** event that
happens regardless of how the session was obtained, which makes it the more reliable anchor.

Practical consequence for triage: **absence of a risky sign-in does not clear a hit on this rule.**
That inversion is the single most common triage mistake on this alert class.

## What the query scores

| Signal | Weight | Rationale |
|---|---|---|
| Forwards to a recipient outside accepted domains | 50 | Mail is leaving the tenant |
| Moves to a suppression folder, or deletes | 30 | Owner is being blinded to their own mail |
| Keywords target payment or security correspondence | 20 | Scoping shows intent, not convenience |
| `MarkAsRead` set | 10 | Only useful for hiding |
| Rule name empty or a single character | 15 | `.` and `..` are operator habits, not user habits |

Anything scoring 80+ has both exfiltration and suppression and should be treated as a confirmed
compromise until disproven, not as a lead.

## Expected FPs, and how to actually clear them

Ranked by how often they appeared in production:

1. **Delegate and shared mailbox forwarding.** Real, common, and the reason the accepted-domain
   list matters. Internal forward targets are excluded by design. Do not "fix" a noisy rule by
   removing the external check.
2. **Migration, journaling and archiving tooling.** These create rules programmatically and burst.
   Clear by actor: if the same service principal or admin account creates rules across many
   mailboxes in a short window with an identical shape, it is tooling. Suppress on the actor,
   not on the rule pattern.
3. **Genuine user housekeeping.** A user filing newsletters into Archive with a keyword rule will
   trip the suppression signal alone (score 30-40). This is why suppression alone is Low, and why
   the score exists instead of a flat boolean.
4. **Out-of-office and handover rules** configured by helpdesk during leave. Verifiable in the
   ticketing system in under a minute.

**Tuning discipline:** exclude by *actor* and by *approved tooling*, never by folder name or by
keyword. Excluding "Archive" because it is noisy removes the mechanism the attacker relies on.
The FP problem here is an identity problem, not a rule-logic problem.

## Investigation Steps

1. Establish whether the forward target is external, and whether the domain is newly registered
   or a lookalike of a partner domain.
2. Pull all mailbox rules currently on the mailbox. Operators frequently create more than one.
3. Look back 12 hours over the user's sign-ins for an IP, ASN or user agent outside their
   baseline. Record what you find; do not require it.
4. Check whether mail matching the rule has already been forwarded, and to whom.
5. Check for a preceding phishing click, an OAuth consent grant, or an MFA method registration.
   The last one is how the operator survives a password reset.
6. Determine blast radius: has the account sent mail internally since the rule appeared? AiTM
   compromises propagate laterally by mailing the victim's own contacts.

## Containment & Response

Order matters. Removing the rule first tells the operator they have been seen while they still
hold a valid token.

1. **Revoke all refresh tokens and sign-in sessions.** This is first. A password reset alone does
   not invalidate a stolen session cookie.
2. Reset the password.
3. Review and remove any MFA methods the operator registered, then re-enrol the user.
4. Remove the mailbox rule, preserving a copy of its definition for the case record.
5. Review OAuth application consents granted by the account.
6. Purge forwarded mail where the tenant retention policy allows, and notify recipients of any
   fraudulent correspondence already sent.
7. Hunt the same IP, user agent and rule shape across every other mailbox in the tenant.

## Deployment notes

- Runs as a scheduled analytics rule at 1 hour with a 1 hour lookback, or as a Defender custom
  detection at the same cadence.
- `AcceptedDomains` must be populated before deployment or every internal delegate forward fires.
- Expected volume in a mid-size tenant: single digits per week at Medium and above.
