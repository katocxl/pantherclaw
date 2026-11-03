# `pclaw compliance` and compliance reports

**Milestone:** M25 ([G0 M25](../g0/M25.md) D300–D304, D311, D312, D529, D531, D545). **Audience:** compliance, audit and security teams.

A compliance report maps your organization's own PantherClaw records to the controls of a framework and shows evidence and gaps. Every report carries this statement, word for word:

> This report shows evidence and gaps. It is not a certification or statement of compliance.

A report has no score, percentage or total. Never describe a report as showing that an organization meets or complies with a framework.

## Frameworks and editions

| Framework | Name in commands | Edition |
|---|---|---|
| OWASP Top 10 for Agentic Applications | `OWASP_ASI` | Team and above |
| NIST AI RMF | `NIST_AI_RMF` | Team and above |
| EU AI Act, deployer duties | `EU_AI_ACT_DEPLOYER` | Business and above |
| ISO/IEC 42001 | `ISO_42001` | Business and above |
| SOC 2 | `SOC2` | Business and above |

## Permissions

- `compliance.read` reads coverage and the list of reports. Auditor, Org Admin and Security Admin hold it.
- `evidence.export` exports a report. Export is ClassSafety, like every evidence export.
- Each source is read under its own permission at organization scope: receipts `evidence.read`, approvals `approval.read`, grants `grant.read`, coverage `coverage.read`, stated agent fields `agent.read`, range and campaign results `redteam.read`.
- Org Admin holds `compliance.read` but not `approval.read`, so approvals read as `outside_permission` for an Org Admin. Export as an Auditor for the full picture.

## Commands

- `pclaw compliance frameworks` lists frameworks, whether your edition has each, and control counts.
- `pclaw compliance coverage NAME --from TIME --to TIME` shows live coverage for a period, in RFC 3339 times.
- `pclaw compliance reports` lists the signed reports made so far, with parameters and digest.
- `pclaw pack create --framework NAME --from TIME --to TIME` exports a signed report.
- `pclaw verify FILE --trust trust.json` re-derives the report offline.

## Reading a report

- **EVIDENCED:** your own real records reach the control, and nothing it reads is a gap.
- **PARTIAL:** some evidence, but with a gap, or only simulated activity, or only tests the server saw hold. Range and campaign results are simulated, so tests alone never go above PARTIAL.
- **GAP:** nothing reached the control, or it could not be read. Each gap gives a reason:
  - `outside_permission`: the report's creator may not read that source. It does not mean there were no records.
  - `reported_only`: the only result was reported, by an edge report or a pass a client observed. A reported result lifts nothing.
  - `ReasonLimit`: a source was cut at its limit. References are capped at 10 per source.
- **STATED:** a person's statement, such as the AI Act role and risk fields on an agent. A statement is never evidence.
- Simulated activity is counted apart in the header and on each cited record.
- A report reads as its creator when the pack job runs. A narrow creator gets more gaps.

Some gaps are expected, not faults:
- ASI01 and ASI06 read as gaps from tests. No library scenario injects instructions or poisons memory or context yet.
- ASI05 is read only by the sandbox scenarios RT-014 and RT-015, so it is a gap in a period with no sandbox range.

The longest period is `MaxPeriod` in `internal/compliance/app/service.go`.

## Re-export

A pack still expires after its usual 7 days. `pc.compliance_reports` keeps the framework, period and digest. The database sets the digest once, and the app cannot delete the row.

To re-export, create a pack with the same framework and period. `compliance.json` holds no time of its own, so the same records give the same digest. New records in the period, or a creator with other permissions, give a different digest. That is correct.

## Offline verification

Verify compliance packs with `pclaw` M25 or later. An older `pclaw` fails a compliance pack on its statement.

`pclaw verify` names these checks:
- `compliance.report`, `compliance.inputs`, `compliance.controls` and `compliance.refs`;
- `compliance.server_records`, shown as not available: a pack does not hold every record it counted.

A report made under another control table than your `pclaw`'s reads as not fully checked, never passed. Update `pclaw`.

## Scenario authors

Library scenarios may carry `asi: [ASI02, ...]` with `asi_why:`, one line per tag naming the OWASP risk the scenario exercises, at most 200 characters. Customer (`CX-`) scenarios may not carry tags, and a customer range never counts toward coverage. Changing tags changes the scenario digest: run `task range:library`. The [range runbook](range.md) has the scenario format.
