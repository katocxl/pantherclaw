# Share checks, owned accounts and read limits

**Milestone:** M30 ([G0 M30](../g0/M30.md) D930–D936; [ADR-0057](../adr/0057-firewall-gaps-from-the-threat-map.md)). **Audience:** an org admin listing the accounts the organization owns, and the people who write grants and answer holds. Runtime firewall.

## 1. Which actions share

Some operations change who can see data. Their packages read the share from the action's own parameters (the agent cannot add or remove an entry):

| Operation | Package | Shares with |
|---|---|---|
| `aws.s3.bucket_policy.put` | `pc.aws.s3` | every account in the policy's principals; `"*"`, a `NotPrincipal` statement or a policy that cannot be parsed counts as public |
| `aws.s3.bucket_acl.put` | `pc.aws.s3` | public for any canned ACL other than `private` |
| `github.repo.visibility.update` | `pc.github` | public when the visibility is `public` |
| `github.repo.transfer` | `pc.github` | the new owner's GitHub organization |

The grant must still name the operation. Then a share **waits for a person** when it is public (`SHARE_PUBLIC`) or names an account the organization has not listed (`SHARE_ACCOUNT_NOT_OWNED`). A share to a listed account adds nothing. The check only adds holds (HR-707).

**An empty list holds every cross-account share.** That is deliberate: list your accounts before agents use these operations.

## 2. List the accounts you own

```bash
pclaw org accounts list
pclaw org accounts add aws_account 123456789012 --reason "production account"
pclaw org accounts add github_org acme --reason "our GitHub organization"
pclaw org accounts remove <id> --reason "account closed"
```

Kinds and formats: `aws_account` (12 digits), `github_org` (1–39 letters, digits and `-`; stored in lower case and compared without case, as GitHub compares names), `email_domain` (a lower-case host name), `gcp_project` and `azure_tenant` (a UUID). Both commands need `org.owned_accounts.manage`, which only people hold.

- **Adding loosens the check**, so it is a protected change: a second person confirms it with a security key before it applies (HR-708). The author cannot confirm their own.
- **Removing is immediate.** Shares to that account hold again at once.
- Both are audited (`org.owned_account_added`, `org.owned_account_removed`).

## 3. Read limits

A grant's count rule can count reads only, or writes only, with `access`:

```json
{"budgets": [{"id": "reads_per_day", "grouping": "task", "operations": ["*"], "access": "read", "max_count": "500", "period": "day"}]}
```

- `access` needs `max_count` and refuses `limit` and `currency` (`BUDGET_ACCESS_NEEDS_COUNT`).
- `"*"` is allowed only with `access`, and only alone (`BUDGET_WILDCARD_NEEDS_ACCESS`).
- The 501st read in the period is refused `COUNT_LIMIT_REACHED`.
- Nothing applies a read limit unless a grant names it. The `read-limits` grant template is an example to copy and adjust.

## 4. Alerts for bulk reads and scheduled sends (Business)

| Rule | Fires when | Basis |
|---|---|---|
| `pc.reads.enumeration` | one run reads 60 distinct targets in 10 minutes | INFERRED |
| `pc.exfil.scheduled_sends` | one agent writes to one public connection from 12 runs in 24 hours | INFERRED |

They raise alerts and never hold or refuse by themselves (HR-709). Targets are counted by a digest, never by their raw ids. Look at the run's reads before acting; a contain step runs only on a CONFIRMED alert.

## 5. When something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| Every transfer or policy change holds | The owned list is empty | Add your accounts (§2) |
| An addition does not take effect | It waits for a second person | Have another admin confirm it with a security key |
