# Onboarding time (F335)

**Milestone:** v0.1.0 preview ([g0/v0.1.0.md](../g0/v0.1.0.md)). **Source:** [quickstart.md](../quickstart.md), which follows [PRODUCT.md](../PRODUCT.md) §6 "First 30 minutes".

The target is 30 minutes from `task demo:up` to the three guided tests. The figure is measured, not guaranteed: it depends on the machine, the network (Docker pulls, the first Go build) and the person.

**Measured by the founder on** `<date>`, following only `docs/quickstart.md`, with a stopwatch.

## Machine and versions

| | |
|---|---|
| Machine (CPU, RAM, disk) | |
| Operating system | |
| Go | |
| Docker | |
| Browser and security key | |
| Commit (`git rev-parse HEAD`) | |
| Warm caches? (Go build cache, Docker images) | |

## Steps

Start the stopwatch before step 1 and note the clock at the start and end of each step.

| Step | Command | Start | End | Minutes | Notes |
|---|---|---|---|---|---|
| 1. Start the demo | `task demo:up` | | | | |
| 2. Sign in | `pclaw login` | | | | |
| 3. Wire Claude Code | `pclaw init` | | | | |
| 4. Enroll and confirm the fingerprint | | | | | |
| 5. Apply the template | `pclaw template apply coding-to-production` | | | | |
| 6. Connect the GitHub App | `pclaw seal` | | | | |
| 7. Run in the sandbox | `pclaw sandbox run` | | | | |
| 8. Read the coverage card | `pclaw coverage list` | | | | |
| 9. Guided tests (allowed, held, blocked) | | | | | |
| **Total** | | | | | |

## Result

| | |
|---|---|
| Total minutes | |
| Within 30 minutes? | |
| Steps that needed help or a second try | |
| Changes to the quickstart afterwards | |
