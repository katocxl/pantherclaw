# Runbook — Release (G2/G3)

**Status:** active from M1 (`v0.0.x` pre-releases exercise the pipeline). Workflow: [`.github/workflows/release.yml`](../../.github/workflows/release.yml), config: [`.goreleaser.yaml`](../../.goreleaser.yaml).

1. **Candidate:** `main` is green (`ci-ok`) and the latest nightly run passed on the candidate commit. Review open private advisories and record the THREAT_MODEL delta (G2 notes in GATES_AND_REVIEW §7).
2. **Tag:** the founder creates a signed annotated tag on the candidate commit and pushes it (the tag ruleset restricts `v*` tags to the founder). While Day-0 item 2 (SSH signing) is open, an unsigned annotated tag (`git tag -a`) pushed by the founder is acceptable; record that in the release notes:
   ```bash
   git tag -s v0.0.1 -m "v0.0.1"   # git tag -a while Day-0 item 2 is open
   git push origin v0.0.1
   ```
   Use SemVer; pre-1.0 versions may break APIs; `-rc.N` suffixes create pre-releases automatically.
3. **Verify job:** fails unless the tagged commit is on `main` and its `ci-ok` check run concluded `success`; then re-runs licence check, race tests and govulncheck on the tagged commit.
4. **Approval (G2/G3):** the `release` job waits for approval of the protected `release` environment (GitHub → Actions → run → *Review deployments*).
5. **Build:** GoReleaser builds static, trimmed binaries (`pantherclaw-server`, `pantherclaw-gateway`, `pclaw`, `pantherclaw-sim`, `pclaw-admin` for linux/darwin/windows × amd64/arm64; `pantherclaw-edge` and `pantherclaw-probe` for linux amd64/arm64), archives, source archive, SBOMs (syft) and `checksums.txt` into a **draft** release with a grouped changelog (Security / Features / Fixes).
6. **Attest:** `actions/attest-build-provenance` attests every file listed in `checksums.txt` (SLSA build provenance, Sigstore via GitHub OIDC).
7. **Images and publish:** the `images` job builds the edge and probe sandbox images (linux/amd64 + arm64, `deploy/sandbox/*.Dockerfile`) from the released binaries, pushes `ghcr.io/katocxl/pantherclaw-edge:<version>` and `ghcr.io/katocxl/pantherclaw-probe:<version>` (no `latest`), attests each image digest, appends both digests to the release notes, then publishes the draft; with immutable releases enabled, assets and tag can no longer change.
8. **Verify as a user would:**
   ```bash
   gh release download v0.0.1 --repo katocxl/pantherclaw --pattern 'pantherclaw_*_linux_amd64.tar.gz'
   gh attestation verify pantherclaw_0.0.1_linux_amd64.tar.gz --repo katocxl/pantherclaw
   ```
9. **Licence note:** each version's Change Date is four years after its first publication (LICENSE parameters).

Users pin the image digests in `sandbox.images` ([sandbox.md](sandbox.md), "Use the released images"). Images carry GitHub build-provenance attestations; cosign signatures are not added yet. Python/npm packages (from M8) publish via trusted publishing bound to the same environment once Day-0 item 4 is done.

**Upgrade notes:** migration `00246` (M21) builds its UNIQUE inside the migration's transaction, so automation runs pause while it builds.

**If the release job fails under harden-runner block mode:** read the blocked endpoint in the job summary, add it to `allowed-endpoints` in a PR (G1), and re-run by deleting and re-pushing the tag only if no release was published.
