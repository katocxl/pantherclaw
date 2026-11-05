# Publishing bundles for PantherClaw

This guide is for vendors and communities who want to ship PantherClaw content for their own products: tool packages with their OpenAPI specs, detection rules, playbooks, fact provider declarations and channel templates (G0 M37; [ADR-0064](../adr/0064-publishers-and-bundles.md)). Orgs install it with the [bundles runbook](../runbooks/bundles.md).

Three things hold for every bundle (founder decisions FQ37-1..3):

- **Data only.** A bundle holds documents of a closed list of kinds. Nothing in it runs as code: not on the server, not on the gateway, not in `pclaw`. Executables, scripts, WASM, binaries and symlinks are refused (HR-797, HR-803).
- **Orgs pin your key.** An org installs your bundles only after an admin pinned your key and confirmed the pin with a security key. The marketplace lists you; it vouches for nobody (HR-795, HR-802).
- **Drafts, not activation.** Everything a bundle installs lands as a draft that the org reviews and signs as it would its own (HR-798).

## 1. Choose a publisher id and create a key

A publisher id matches `^[a-z][a-z0-9-]{2,31}$`, for example `acme-tools`. Every item you publish is named `ext.<publisher>.<name>`, for example `ext.acme-tools.ticket-sync`. `pc.` and `org.` names and other publishers' namespaces are refused.

```bash
pclaw publisher key create --publisher acme-tools --out acme-tools.key --passphrase-file passphrase.txt
```

This writes the private key to `acme-tools.key` (mode 0600; encrypted with the passphrase, which must be long enough, or unencrypted when `--passphrase-file` is left out) and the public key, as a JWK, to `acme-tools.key.pub`. Neither file may exist yet. It prints the key id (`publisher-acme-tools-<22 characters>`) and the fingerprint, the lowercase hex SHA-256 of the raw Ed25519 public key. Keep the private key offline. Publish the fingerprint where orgs already trust you: your website, your release notes, your contract.

## 2. Lay out a bundle

```bash
pclaw bundle init --publisher acme-tools --name ext.acme-tools.starter ./starter
```

A bundle directory holds `bundle.json` and the item files under `items/<kind>/`:

```
starter/
  bundle.json
  items/detection_rule/high-volume.yaml
  items/playbook/contain.yaml
  items/tool_package/package.yaml
  items/openapi_spec/openapi.yaml
```

`bundle.json` (spec `pc-bundle/1`):

| Field | What it holds |
|---|---|
| `spec` | `pc-bundle/1` |
| `publisher` | your publisher id |
| `name` | `ext.<publisher>.<slug>` |
| `version` | semver, rising with every release |
| `title`, `summary` | for people |
| `items[]` | `kind`, `name`, `path`, `sha256`, `size` of each item file; `pclaw bundle build` fills in `sha256` and `size` |

Unknown fields are refused. Limits: at most 64 items, 1 MiB per item and 8 MiB in all; paths only of the form `items/<kind>/<file>`.

### Item kinds

| Kind | Document | Installs as |
|---|---|---|
| `tool_package` | a `package.yaml` as for the org's own packages, optionally with `simulator: {kind: openapi, spec: <item path>}`; the data-driven OpenAPI simulator is the only one allowed | a DRAFT tool package the org reviews and signs |
| `openapi_spec` | an OpenAPI document a tool package refers to | part of that tool package |
| `detection_rule` | a custom rule document with id `ext.<publisher>.…` | a DRAFT custom rule (Business) |
| `playbook` | an automation definition from the closed step catalog | a DRAFT automation (Team) |
| `facts_declaration` | a fact provider declaration (no reader) | a DRAFT declaration or a template |
| `channel_template` | an existing channel kind and its non-secret fields | a template; the org creates the channel and its secrets (HR-801) |

A channel template field named or shaped like a secret (a token, secret, password, key, or a webhook URL carrying credentials) is refused.

## 3. Lint, build, sign, verify

```bash
pclaw bundle lint ./starter                        # decode every item; nothing is executed
pclaw bundle build ./starter --out ext.acme-tools.starter-1.0.0.pcbundle
pclaw bundle sign ext.acme-tools.starter-1.0.0.pcbundle --key acme-tools.key --passphrase-file passphrase.txt
pclaw bundle verify ext.acme-tools.starter-1.0.0.pcbundle --fingerprint <hex>
pclaw bundle inspect ext.acme-tools.starter-1.0.0.pcbundle
```

- `lint` decodes the manifest and each item with the same decoders the server uses.
- `build` writes the digests and sizes into `bundle.json` and zips the bundle.
- `sign` adds `bundle.jws`: a compact JWS over the exact `bundle.json` bytes (EdDSA, typ `pc-bundle+jwt`, valid for at most 400 days).
- `verify` checks the signature against a public key file (`--public-key`, the `.pub` file) or a fingerprint, and every digest.
- `inspect` prints the manifest and the signature's claims.

The example bundle [`examples/bundles/ext.example.starter/`](../../examples/bundles/ext.example.starter/) holds one detection rule, one playbook and one OpenAPI tool package.

## 4. Release

- Publish the `.pcbundle` file at an https URL with its SHA-256.
- Raise the version with every release. Orgs refuse a lower version than the one they have (rollback) and a second, different file with the same version (equivocation).
- Optionally submit a listing to the marketplace: `marketplace/listings/<publisher>.json` with your display name, homepage, key fingerprints and bundles ([format](../../marketplace/listings/README.md)). A listing is not an endorsement.

## 5. Revoke

If your key leaks or a bundle is harmful, sign a revocation statement with any key of yours an org pinned: a compact JWS, typ `pc-bundle-revocation+jwt`, with `publisher`, `scope` (`KEY` with the `kid`, or `BUNDLE` with the `name` and the highest revoked version) and `iat`. Post it at the `revocations_url` orgs pinned with your key; PantherClaw fetches it daily, and an org can also submit it at once. Revocation stops the affected installs immediately (HR-799, HR-800). Then release a fixed, higher version.

Orgs do not depend on you to revoke: an admin can revoke your key or a bundle at any time (R-91).
