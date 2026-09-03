# User clicked through to a credential harvesting page from a non prevalent sender

| | |
|---|---|
| **ATT&CK** | T1566.002 Spearphishing Link, leading to T1078.004 |
| **Tactic** | Initial Access, Credential Access |
| **Data source** | `UrlClickEvents`, `EmailEvents`, `AADSignInEventsBeta` |
| **Status** | Validated against fixtures |

## Hypothesis

Phishing delivery alerts are abundant and mostly uninteresting, because the control usually
holds. The cases worth an analyst's time are the ones where it did not: the mail was delivered,
the user clicked, the URL was not blocked at click time, and a session may now exist that the
user did not create.

## Why sender prevalence rather than URL reputation

URL reputation is the obvious signal and it is the one that already failed. If the URL were known
bad, the click would have been blocked and this rule would not fire. Reputation systems lag
behind newly registered infrastructure by hours to days, which is precisely the window an
operator uses.

Sender prevalence does not depend on anyone having seen the infrastructure before. It asks a
different question: has this organisation ever corresponded with this domain? Credential
harvesting is almost always sent from infrastructure with no history with the target, while the
mail body is crafted to look routine. That asymmetry is the detection.

The cost is that legitimate first contact also has no history, which is the source of nearly all
the false positives below. That tradeoff is accepted deliberately, and the rule is scoped to
clicks rather than deliveries specifically to keep the volume manageable.

## Signal weighting

| Signal | Weight |
|---|---|
| Unknown sender and the click was not blocked | 40 |
| URL contains authentication related terms | 30 |
| Mail was delivered rather than junked or quarantined | 15 |
| Clicked within 10 minutes of delivery | 15 |
| Mail carried 8 or more URLs | 10 |

Clicking within ten minutes scores because urgency is manufactured by the lure. A user who clicks
a marketing mail three days later is behaving differently from one who clicks a password expiry
notice immediately.

## False positives, and the honest ratio

This rule is Medium severity, not High, and that is deliberate. It will produce more false
positives than the other rules in this repository.

1. **Marketing, recruitment and vendor outreach.** The dominant class by a wide margin. Every
   cold email is by definition from a sender with no history.
2. **Phishing simulations.** Will swamp everything else if not excluded. Put the simulation
   infrastructure in `SimulationSenders` before deploying, not after.
3. **Newly onboarded suppliers.** Genuine first contact from a real business partner.
4. **Newsletters a user subscribed to recently.**

Do not attempt to tune these to zero. The rule's value is that it narrows a very large delivery
alert population down to a small reviewable set that contains the real incidents. A ten to one
false positive ratio on ten alerts a day is a good trade; the same ratio on a thousand is not,
which is why the click condition and the prevalence floor both matter.

## Triage steps

1. Look at the URL and the redirect chain. Where it finally lands answers most of the question,
   and the chain is often more revealing than the initial link.
2. Check the domain's registration age. Days old is close to conclusive.
3. Run the escalation query. A successful sign in within two hours of the click, from an IP, ASN
   or user agent outside the user's baseline, converts this from a click to a compromise.
4. If a sign in occurred, go straight to the mailbox rule detection in this repository.
   Rule creation is the usual next action and is often the only other artefact.
5. Check whether other users received mail from the same sender. Campaigns are sprayed.
6. Ask the user what they entered. Faster and more reliable than inferring it, and the answer
   determines whether this is a credential reset or an incident.

## Response playbook

1. If a sign in followed the click, revoke sessions and refresh tokens first, then reset the
   password. Order matters, since a reset alone leaves a stolen session cookie valid.
2. Review MFA methods on the account for anything registered after the click.
3. Block the URL, its redirect chain and the sender domain.
4. Purge the mail from every mailbox that received it.
5. Check for mailbox rules created after the click.
6. Hunt the sender domain and URL pattern across the tenant for other recipients and other
   clickers.
7. Feed the domain to the mail filtering team so the next wave is blocked at delivery.

## Deployment notes

- Requires `UrlClickEvents`, which needs Safe Links enabled. Without it this rule cannot fire at
  all and its silence means nothing.
- Run the simulation baseline query before deploying. This is the single highest value tuning
  step for this rule.
- Schedule at 1 hour. Credential replay follows a successful harvest within minutes, so this is
  one of the few detections where latency directly changes the outcome.
