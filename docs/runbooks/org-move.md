# Runbook — Moving the repositories to the GitHub organization

**Milestone:** M13 wave 3 ([G0 M13](../g0/M13.md) F8; [UPGRADES](../UPGRADES.md)). **Audience:** the founder. Run it once, after GitHub has transferred both repositories to the organization. Until then the module path stays `github.com/katocxl/pantherclaw`.

## 1. Before

1. Create the free GitHub organization and transfer `katocxl/pantherclaw` (and the private repository) to it. GitHub redirects the old URLs, so nothing breaks in the meantime.
2. Merge or close the open pull requests first: the change touches almost every Go file, so every open branch conflicts with it.

## 2. Rewrite (one pull request)

From Git Bash at the repository root, on a fresh branch from `origin/main`:

```bash
git switch -c chore/org-move origin/main
# dry run: lists every file and how many lines reference the old location; writes nothing
tools/scripts/move-module-path.sh github.com/katocxl/pantherclaw github.com/<org>/pantherclaw
# apply: rewrites the files and regenerates the protobuf code with buf
tools/scripts/move-module-path.sh --apply github.com/katocxl/pantherclaw github.com/<org>/pantherclaw
```

`--apply` rewrites, in every tracked text file:

- the module path: the `module` and `require`/`replace` lines of every `go.mod` (the root, `sdk/go`, `tools` and `tools/pins/*`), Go imports, the `-X` ldflags in `.goreleaser.yaml` and the Dockerfiles, `go_package_prefix` in both `buf.gen.yaml` files, the `go_type` imports in `sqlc.yaml`, and `https://github.com/katocxl/pantherclaw…` links in docs, the chart and the docs site template;
- `raw.githubusercontent.com/katocxl/pantherclaw` (the `install.sh` links) and the bare slug `katocxl/pantherclaw` (`gh … --repo`, `REPO=` in `install.sh`);
- `owner:` of the GoReleaser release target;
- the image names `ghcr.io/katocxl/…` → `ghcr.io/<org>/…`, because an organization repository cannot push to the personal namespace. Pass `--keep-images` to leave them. Released `pclaw` binaries keep the image digests they embed, and the old images stay where they are.

It then runs `buf generate` for both buf workspaces, because the generated `*.pb.go` descriptors hold `go_package` as length-prefixed bytes that a text rewrite would corrupt; `*.pb.go` files are never rewritten as text. `--no-gen` skips that step (then run `task gen` yourself).

It leaves alone: `go.sum` and lock files (the repository's own modules are not in them), untracked files, the person `@katocxl` (CODEOWNERS, profile links in CODE_OF_CONDUCT, COMMERCIAL_LICENSE and TRADEMARKS), and the historical records `docs/g0/`, `docs/adr/` and `docs/UPGRADES.md`. If the repository is also renamed, check `release.github.name` in `.goreleaser.yaml` by hand.

## 3. Check and land

```bash
go tool -modfile=tools/pins/task/go.mod task gen:check   # no diff after a full regeneration
go tool -modfile=tools/pins/task/go.mod task check
go build ./... && (cd sdk/go && go build ./...) && (cd tools && go build ./...)
git grep -n katocxl/pantherclaw -- ':!docs/g0' ':!docs/adr' ':!docs/UPGRADES.md'   # only this runbook and the script
```

Commit it as one change (`chore: move the module path to github.com/<org>/pantherclaw`) and open one pull request. It changes `.github/` (the release workflow's image names, the issue template links), so it gets no auto-merge: merge it yourself once `ci-ok` is green.

## 4. After

- Update the repository settings that name the old owner: package names on PyPI and npm trusted publishers (workflow `release.yml`), the Sigstore identity the staging deploy verifies (F10, `.github/workflows/image.yml@refs/heads/main` under the new owner), branch protection and the `ci-ok` rule, and the CodeRabbit and CLA Assistant installations.
- The next release publishes images under `ghcr.io/<org>/`; update the Helm values and docs that pin a digest from an earlier release.
- Ask the Go module proxy for the new path once the first tag exists (`GOPROXY=https://proxy.golang.org go list -m github.com/<org>/pantherclaw@<tag>`).
- Keep the personal account `katocxl` and never create a new repository named `pantherclaw` under it: GitHub keeps redirecting the old URLs only while that name is unused, and a free name lets anyone serve code under the old module path or install URL (THREAT_MODEL T-181).
