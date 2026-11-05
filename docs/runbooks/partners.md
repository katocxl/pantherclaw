# Work with an MSSP partner

A managed security service provider (MSSP) can watch and help many customers from its own PantherClaw org (G0 M38; [ADR-0065](../adr/0065-partners-and-shared-indicators.md); HR-810..816). The customer approves each partner link with a security key, for at most 90 days, and can revoke it at any time. Under a link the partner's people read what a support session reads and propose policy or pack rollouts, which only ever become drafts in the customer org. Every partner call is in the customer's audit log.

Partner and customer must be on the same PantherClaw deployment. The partner org needs the Enterprise edition (`PartnerAccess`); the customer needs no particular edition.

## 1. Permissions

| Permission | Who has it | What it allows |
|---|---|---|
| `partner.manage` | Org Admin | Request, renew and withdraw: the partner side of links and proposals |
| `partner.approve` | Org Admin, Security Admin (a person only) | Approve, deny and revoke links: the customer side |
| `partner.operate` | Org Admin, Security Admin in the partner org (a person only) | Open a partner session in a customer |
| `partner.read` | Org Admin, Security Admin, Auditor | List links, the customer summary and proposals |

Custom roles may grant any of them; `partner.approve` and `partner.operate` still need a person.

## 2. Link a partner (both orgs)

1. **The partner requests a link** with `RequestPartnerLink`: the customer org's id, 1 to 90 days, the scopes (READ always; PROPOSE to send rollout proposals) and a reason. The request is audited `partner.link_requested` in both orgs and expires if nobody decides within seven days.
2. **The customer decides** in the browser at `<server URL>/partners/links/<id>/decide`. The page shows the partner org, the scopes, the days and the reason; Approve and Deny ask for your security key (a WebAuthn step-up). `DecidePartnerLink` over the API always answers `STEP_UP_REQUIRED`. The person who asked can never decide.
3. The window starts at the approval and ends `duration_days` later. When it ends the link is EXPIRED and every partner session of it ends. To continue, the partner asks again with `RenewPartnerLink` and the customer decides again.
4. **The customer revokes** with `RevokePartnerLink` at any time, without a step-up. Revoking ends every partner session of the link at once.

`ListPartnerLinks` and `GetPartnerLink` show the link to both orgs and nobody else.

## 3. Open a customer (partner side)

`ListPartnerCustomers` lists, for each ACTIVE link, the customer's name, when the link ends, how many approvals are waiting, how many alerts are open and when the last decision was made. Counts only: no records, agent names or people (HR-816). Each read is audited `partner.summary_read` in that customer's org.

To look inside a customer, open `<server URL>/partners/customers/<customer org>/open` while signed in to the partner org, and confirm with your security key. You get a partner session in that customer's console:

- It reads what a support session reads and can send rollout proposals; nothing else. Approvals, step-ups and every change are refused (HR-811, HR-812).
- It ends after 12 hours, after 30 idle minutes, when the link ends, or with Sign out (`POST /partners/logout`).
- Every call checks again that the link is ACTIVE, the partner org still has the edition, and you are still enabled and hold `partner.operate`. Every call is audited `partner.call` in the customer org, with actor `partner/<partner org>/<user id>`.

## 4. Propose a rollout (partner side)

With a PROPOSE link, `ProposeRollout` sends a policy version (a policy document) or a pack with its environment, agents, cohort and parameters, up to 256 KiB, to one or more customers. From a partner session it goes to that customer; from the partner org a person with `partner.manage` may send it to many customers at once, grouped by a template id. A proposal expires after 30 days; `WithdrawPartnerProposal` takes it back.

## 5. Review a proposal (customer side)

`ListPartnerProposals` and `GetPartnerProposal` show what was sent. A person with `policy.author`:

- **Accepts** it with `AcceptPartnerProposal`, which creates a DRAFT only: a policy version (its `policy.version_created` record names `origin = partner:<partner org>`) or a pack draft. Nothing publishes or rolls out.
- **Declines** it with `DeclinePartnerProposal` and a reason.

From the draft, the usual publish and rollout flow applies, with one difference: publishing or rolling out a partner-origin version always needs two distinct customer people with security keys (HR-815). If the org has fewer than two people who may publish, the change request waits with `NEEDS_SECOND_PERSON`.

## 6. Audit

| Kind | Org | When |
|---|---|---|
| `partner.link_requested`, `_approved`, `_denied`, `_revoked`, `_expired` | both | Link events |
| `partner.session_opened`, `partner.session_ended` | both | A partner session starts or ends |
| `partner.call` | customer | Every call in a partner session |
| `partner.summary_read` | customer | Each customer read by `ListPartnerCustomers` |
| `partner.proposal_created`, `_accepted`, `_declined`, `_withdrawn`, `_expired` | both | Proposal events |

## 7. Troubleshooting

- **`UNAUTHENTICATED` on every partner call:** the session ended, the link has ended, the partner org lacks the Enterprise edition, or your account was disabled or lost `partner.operate`. Open the customer again after fixing it.
- **`NO_PARTNER_LINK` when opening a customer:** there is no ACTIVE link to that customer.
- **The decide page shows no buttons:** you lack `partner.approve` or the link is no longer REQUESTED.
- **A change request stays waiting:** it publishes a partner-origin version and needs a second customer person.
