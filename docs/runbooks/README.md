# Runbooks

Operational procedures. Each runbook is completed (from stub to tested procedure) in the milestone named in its header, and exercised at least once before v1.0.

| Runbook | Milestone | Purpose |
|---|---|---|
| [key-rotation.md](key-rotation.md) | M1 / M6 / M7 | Rotate signing keys, DEKs, KEKs, gateway broker keys and sealed credentials; the internal CA |
| [gateway.md](gateway.md) | M6 | Enroll, renew, check and revoke gateways |
| [kill-switch.md](kill-switch.md) | M6 | Engage and restore the org-wide emergency stop |
| [evidence-verification.md](evidence-verification.md) | M7 | Investigate an evidence integrity failure and resume checkpointing |
| [retention.md](retention.md) | M7 | Set up the retention role and job; set retention periods, legal holds and payload capture |
| [backup-restore.md](backup-restore.md) | M13 | Backups, point-in-time recovery, restore drill |
| [incident-response.md](incident-response.md) | M10 | Respond to a security incident in PantherClaw itself |
| [dmca-takedown.md](dmca-takedown.md) | M0 | Handle copies that violate the licence or trademark |
| [release.md](release.md) | M1 | Cut, verify and publish a release (G2/G3) |
| [workload-identity.md](workload-identity.md) | M3 | Enroll workloads, set up GitHub Actions and Kubernetes attestation, run pull-request bots safely |
