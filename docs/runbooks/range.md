# Adversarial range (`pclaw redteam`, `task range`)

**Milestone:** M12 · **Owner:** security engineers, agent owners and the maintainers (`redteam.run`, `redteam.read`) · **Status:** procedure as designed in G0 M12; CLI flags are "as designed in G0 M12; confirm at exit"

How to run the attack scenarios against your own policies, grants and packages, read the results, produce a signed report, and use the regression gate. Background: [g0/M12.md](../g0/M12.md), [ADR-0023](../adr/0023-adversarial-range.md), HR-120 and HR-220..HR-226.

## 1. What the range is, and is not

- It runs at least 30 scripted attacks (the coding-agent suite first, then the platform suite) against the real policies, grants and tool packages of your organization, and only against simulators (`pantherclaw-sim`). It never touches a real system or a real credential.
- A range run belongs to a **range agent**. The server marks its runs, transactions and connections as simulated, and every receipt says `simulated: true`. A range run that reaches a real connection is denied (`SIMULATION_MISMATCH`), and so is the reverse. Policies never see the mark, so they behave exactly as for a real agent.
- Simulated activity changes nothing real agents depend on: no real budget, quarantine, coverage, containment or kill switch is touched, and approval pages and notifications are labelled SIMULATED.
- A report is **tested-control evidence against simulated targets. It is not a compliance certification**, and a pass means "these attacks failed against these versions", not "the system is secure".
- A `SKIPPED` scenario (a needed capability is missing) is not a pass.

| Edition | What you get |
|---|---|
| Community | The engine, `pclaw redteam run`, the coding-agent scenarios and an unsigned `summary.json` |
| Team | Signed assurance reports (evidence packs) and the `--baseline` gate |
| Business | The full scenario library (the platform suite) |

Range agents do not count toward the agent limit; each organization may have at most 5.

## 2. Set up

All CLI flags below are as designed in G0 M12; confirm at exit.

1. **Start the simulators** on loopback or a private address, one per connection you want to test:
   ```bash
   pantherclaw-sim payments ...   # payments target
   pantherclaw-sim mcp ...        # MCP target
   pantherclaw-sim github ...     # GitHub target (coding-agent suite)
   ```
   Each serves `GET /.well-known/pantherclaw-sim?nonce=<hex>`; the gateway uses it to confirm that it really is a simulator.
2. **Use a dedicated range gateway** whose egress reaches only the loopback or private addresses of those simulators. Do not point the range at your production gateway's network.
3. **Plan the setup** as a person, then apply it:
   ```bash
   pclaw redteam setup --dry-run --like-grant <grant id> ...   # prints the plan, changes nothing
   pclaw redteam setup --like-grant <grant id> ...
   ```
   It creates a range agent, simulated twin connections for the chosen packages (their base URLs, allowed hosts and host overrides must all be loopback or private IP literals, otherwise `SIMULATED_TARGET_NOT_LOCAL`), and a grant for the range agent shaped like the real grant you name. Each step is audited. It prints the instance enrolment and the simulator commands.
4. **Enroll the range instance** with the printed enrolment, as for any workload ([workload-identity.md](workload-identity.md)), and keep its workload file for the run.

## 3. Run

```bash
pclaw redteam run --suite coding-agent \
  --scenarios redteam/scenarios \
  --workload-file <range instance file> \
  --gateway <gateway url> \
  [--interactive] [--baseline <pack.zip>] [--out <dir>]
```

- `--suite` is `coding-agent`, `platform` or `all`. The platform suite needs Business (`EDITION_REQUIRED` otherwise).
- The command always starts a range first, runs each scenario through the live driver, records each result with the server, finishes the range and writes `summary.json` and a text table to `--out`.
- Steps that need a person (approvals, declines) run only with `--interactive`: the command prints the approval link and waits. Without it those scenarios are `SKIPPED`.
- It never executes a delegated allow. The live driver does not support `sim.mutate`, `operator.*` or `server.read` with `org: other`; scenarios using them are `SKIPPED` ("driver lacks <kind>") and, with the `harness_only` ones (RT-029, RT-034, which run in a separate non-range stack), run fully only under `task range`.

### Reading the results

`summary.json` lists, per scenario, a verdict and per step the expected and observed outcome:

| Verdict | Meaning |
|---|---|
| `PASS` | Every step matched its expectation |
| `FAIL` | A step did not match; the scenario stopped there |
| `ERROR` | The driver failed or the 60 s scenario timeout passed |
| `SKIPPED` | A required capability is missing, a person step without `--interactive`, or the live driver lacks a step kind ("driver lacks <kind>": `sim.mutate`, `operator.*`, `server.read` with `org: other`). Never `ERROR`; the summary lists each skip with its reason |

Steps the server can observe (a transaction, a probe report) are marked `observed_by = server`; the server's value wins over the runner's claim, and a difference is flagged `MISMATCH`. Other steps are `client` observations. Read `FAIL` first: it means a control did not do what the scenario expected, and the decisive control is named in the step.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No `FAIL`, no `ERROR`, no regression against the baseline. `SKIPPED` without a baseline exits 0 but is listed |
| 1 | Any `FAIL`, any `ERROR`, or any regression against the baseline |
| 2 | Usage or infrastructure error before scenarios ran, a baseline that cannot be used, or a failed `RecordResult` (the command carries on and exits 2 at the end; scenarios that were not recorded are missing from the report) |

## 4. Signed report (Team)

```bash
pclaw redteam list
pclaw redteam report <range id> --out pack.zip
pclaw verify pack.zip --trust <trust file>
```

The report is an evidence pack of scope `range`: the assurance document (per-scenario verdicts, steps, who observed them, decisive controls, policy and package versions, counts by category) and every referenced transaction's receipts. `pclaw verify` checks the pack offline, as in [evidence-verification.md](evidence-verification.md), and additionally that every receipt says `simulated: true` and that each server-observed step matches its decision receipt. Exporting needs Team and the `evidence.export` permission.

## 5. The baseline gate in your pipeline (Team)

Keep a verified pack of a good run as the baseline. A regression is a scenario that passed in the baseline and now fails, errors, is skipped or is missing; a changed scenario digest is reported but still compared. The command verifies the baseline pack offline before comparing.

```yaml
# .github/workflows/range.yml (example)
name: range
on:
  pull_request:
    paths: ['policies/**', 'grants/**', 'packages/**']
jobs:
  range:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Start simulators
        run: ./ci/start-simulators.sh      # your script: pantherclaw-sim on loopback
      - name: Run the range
        run: |
          pclaw redteam run --suite all --scenarios redteam/scenarios \
            --workload-file "$RANGE_WORKLOAD_FILE" --gateway "$RANGE_GATEWAY" \
            --baseline baseline/range-pack.zip --trust "$TRUST_FILE" --out range-out
        env:
          RANGE_WORKLOAD_FILE: ${{ secrets.RANGE_WORKLOAD_FILE }}
          RANGE_GATEWAY: ${{ vars.RANGE_GATEWAY }}
          TRUST_FILE: ci/trust.json
      - uses: actions/upload-artifact@<full commit SHA>   # pin it, as this repository's workflows do
        if: always()
        with: { name: range-out, path: range-out }
```

The baseline must verify offline against the trust file, be fully verifiable (no receipt reported as not available) and belong to the same organization. Otherwise the command exits 2 and no range is started. Pin every action by commit SHA, as this repository's workflows do.

Use a service account holding `redteam.run` for the pipeline (it is not human-only). Update the baseline deliberately, in a reviewed change, after you have read the new report.

## 6. This repository's local gate

CI is suspended (EX-004), so the gate is local:

```bash
task up PROFILE=test      # the test stack on 127.0.0.1:5433
task range                # every scenario against simulators
SANDBOX=1 task range      # also the sandbox scenarios (needs Docker 28+, see sandbox.md)
```

A pull request that touches `internal/authority`, `internal/gateway`, `internal/sandbox`, `internal/redteam`, `packages/` or `redteam/` runs `task range` (with `SANDBOX=1` when `internal/sandbox` changed) and reports the result in its description. A `range` job exists in the disabled `ci.yml` and switches on with the other workflows before the first release tag.

## 7. Troubleshooting

| You see | Cause and fix |
|---|---|
| `simulator_unverified` (a local refusal by the gateway) | The target did not answer the simulator handshake with the right nonce, or its host is not a loopback or private literal. Start `pantherclaw-sim` for that connection, check the address, and retry; nothing was sent to the target |
| `SIMULATION_MISMATCH` | A simulated run met a real connection, or a real run met a simulated one. Use the range agent with its twin connections only. Scenario RT-022 expects this denial |
| A hold with reason `SECRET_IN_PAYLOAD` | The action carried a known credential format (a GitHub token, a private key, an AWS or Slack key, a PantherClaw token), also inside base64 JSON string values one level deep. A person approves it if it is a fixture; RT-010 expects the hold. The report shows the kind and location, never the value |
| A `SECRET_IN_PAYLOAD` hold whose finding is `scan_incomplete` | The scan stopped at its part cap, or a base64 value decoded to more than 1 MiB, so the gateway could not rule out a secret and holds for a person. Reduce or split the payload; a person may approve the hold if the content is a known fixture |
| `secret_in_payload` (a local refusal) | The action carried the dispatching connection's own static credential. Remove it; RT-011 expects the refusal |
| `RANGE_AGENT_LIMIT` | The organization already has 5 range agents. Reuse one or retire another |
| `EDITION_REQUIRED` | The platform suite needs Business; signed reports and `--baseline` need Team. On a dev server, signed reports are exercised in tests with injected entitlements |
| Scenarios `SKIPPED` | A capability is missing (sandbox, second organization, a person). Add `--interactive`, run with Docker for the sandbox scenarios, or accept that they do not count as passed |
| `SIMULATED_TARGET_NOT_LOCAL` | A simulated connection names a host that is not a loopback or private IP literal; the base URL, allowed hosts and host overrides must all be |
| `RANGE_RECORD_INVALID` / `INVALID_STEPS` | The server refused a recorded result: a transaction may back steps of only one scenario per range; a step that cites a probe report needs that probe's result in the report; a `PASS` must record exactly the scenario's declared step count (`FAIL` and `ERROR` may record fewer); a probe result of `error` makes a citation of that report invalid, so record such a scenario as `ERROR` without citing the report |
| Scenarios listed as "driver lacks <kind>" | Expected for the live driver; run them under `task range` |

Report anything unexpected to the maintainers rather than editing a control or an expectation to make a scenario pass.
