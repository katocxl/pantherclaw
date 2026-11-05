# Publishing bundles for PantherClaw

This guide is for vendors and communities who want to ship PantherClaw content for their own products: tool packages with their OpenAPI specs, detection rules, playbooks, fact provider declarations and channel templates (G0 M37; [ADR-0064](../adr/0064-publishers-and-bundles.md)). Orgs install it with the [bundles runbook](../runbooks/bundles.md).

Three things hold for every bundle (founder decisions FQ37-1..3):

- **Data only.** A bundle holds documents of a closed list of kinds. Nothing in it runs as code: not on the server, not on the gateway, not in `pclaw`. Executables, scripts, WASM, binaries and symlinks are refused (HR-797, HR-803).
- **Orgs pin your key.** An org installs your bundles only after an admin pinned your key and confirmed the pin with a security key. The marketplace lists you; it vouches for nobody (HR-795, HR-802).
- **Drafts and templates, not activation.** Everything a bundle installs lands as a draft or a template that the org reviews, and signs where it signs its own (HR-798).

## 1. Choose a publisher id and create a key

A publisher id matches `^[a-z][a-z0-9-]{2,31}$`, for example `acme-tools`. Every item you publish is named `ext.<publisher>.<name>`, for example `ext.acme-tools.ticket-sync`. `pc.` and `org.` names and other publishers' namespaces are refused.

```bash
pclaw publisher key create --publisher acme-tools --out acme-tools.key --passphrase-file passphrase.txt
```

This writes the private key to `acme-tools.key` (mode 0600; encrypted with the passphrase of at least 16 characters, or unencrypted when `--passphrase-file` is left out) and the public key, as a JWK, to `acme-tools.key.pub`. Neither file may exist yet. It prints the key id (`publisher-acme-tools-<22 characters>`) and the fingerprint, the lowercase hex SHA-256 of the raw Ed25519 public key. Keep the private key offline. Give orgs the `.pub` file and publish the fingerprint where they already trust you: your website, your release notes, your contract. An org needs both: the key file to pin, and the fingerprint to check it.

## 2. Lay out a bundle

```bash
pclaw bundle init --publisher acme-tools --name ext.acme-tools.starter ./starter
```

A bundle directory holds `bundle.json` and the item files under `items/<kind>/`:

```
starter/
  bundle.json
  items/detection_rule/high_volume.yaml
  items/playbook/contain.yaml
  items/tool_package/package.yaml
  items/openapi_spec/openapi.yaml
```

`bundle.json` (spec `pc-bundle/1`):

| Field | What it holds |
|---|---|
| `spec` | `pc-bundle/1` |
| `publisher` | your publisher id |
| `name` | `ext.<publisher>.<slug>` (lowercase letters, digits and dashes) |
| `version` | `MAJOR.MINOR.PATCH`, rising with every release |
| `title`, `summary` | for people (128 and 1024 bytes of plain text at most) |
| `items[]` | `kind`, `name`, `path`, `sha256`, `size` of each item file, and for a tool package optionally `simulator`; `pclaw bundle build` fills in `sha256` and `size` |

Unknown fields are refused. Limits: at most 64 items, 1 MiB per item and 8 MiB uncompressed in all, and the `.pcbundle` file itself at most 960 KiB so that it fits one upload; paths only of the form `items/<kind>/<file>`. Every item file is text.

### Item kinds

| Kind | Document | Installs as |
|---|---|---|
| `tool_package` | a `package.yaml` as for the org's own packages, named as the item; its manifest entry may add `"simulator": {"kind": "openapi", "spec": "items/openapi_spec/<file>"}`, the data-driven OpenAPI simulator being the only one allowed | a DRAFT tool package the org reviews and signs with its own org package key; importing it needs the matching installed item |
| `openapi_spec` | an OpenAPI 3.0 or 3.1 document; each one must be named by a tool package's simulator | part of that tool package |
| `detection_rule` | a custom rule document whose id is the item name, `ext.<publisher>.<name>` (lowercase letters, digits and underscores after the publisher), basis at most INFERRED, edition business | a DRAFT custom rule (Business) |
| `playbook` | an automation definition from the closed step catalog; the automation is named after the item, with dots and underscores turned into dashes (at most 52 characters, so `ext.acme-tools.contain` becomes `ext-acme-tools-contain`) | a DRAFT automation (Team) |
| `facts_declaration` | a fact provider declaration: `provider` and its `facts` (no reader) | a TEMPLATE record; a person registers a provider through the existing flow |
| `channel_template` | an existing channel kind, its event types, a minimum severity and non-secret settings | a TEMPLATE record; the org creates the channel and its secrets (HR-801) |

A channel template setting named like a secret (token, secret, password, key, credential, auth, cookie, session, webhook, url and the like) or holding a value shaped like one (a known token prefix, a PEM block, a JWT, a long base64 or hex run, or any URL) is refused.

## 3. Lint, build, sign, verify

```bash
pclaw bundle lint ./starter                        # decode every item; nothing is executed
pclaw bundle build ./starter --out ext.acme-tools.starter-1.0.0.pcbundle
pclaw bundle sign ext.acme-tools.starter-1.0.0.pcbundle --key acme-tools.key --passphrase-file passphrase.txt
pclaw bundle verify ext.acme-tools.starter-1.0.0.pcbundle --public-key acme-tools.key.pub --fingerprint <hex>
pclaw bundle inspect ext.acme-tools.starter-1.0.0.pcbundle
```

- `lint` decodes the manifest and each item, of a directory or a file, with the same decoders the server uses. It does not check a signature.
- `build` computes each item's digest and size into `bundle.json` and zips the bundle, unsigned, to a new file; the directory is not changed.
- `sign` adds `bundle.jws`: a compact JWS over the exact `bundle.json` bytes (EdDSA, typ `pc-bundle+jwt`, valid for 365 days by default and at most 400 with `--expires-days`). It replaces the file, or writes `--out`.
- `verify` checks the signature and every digest against the public key file; `--fingerprint` also checks that the key file is the one announced. A fingerprint alone cannot check a signature and is refused.
- `inspect` prints the file's SHA-256, the manifest and the signature's claims, without verifying them.

The example bundle [`examples/bundles/ext.example.starter/`](../../examples/bundles/ext.example.starter/) holds one OpenAPI tool package with its spec, one detection rule and one playbook; `pclaw bundle lint examples/bundles/ext.example.starter` decodes it.

## 4. Release

- Publish the `.pcbundle` file at an https URL with its SHA-256.
- Raise the version with every release. Orgs refuse a lower version than the one they have (rollback) and a second, different file with the same version (equivocation).
- Optionally submit a listing to the marketplace: `marketplace/listings/<publisher>.json` with your display name, homepage, keys (each public key with its fingerprint) and bundles ([format](../../marketplace/listings/README.md)). A listing is not an endorsement.

## 5. Revoke

If your key leaks or a bundle is harmful, sign a revocation statement with any key of yours an org pinned: a compact JWS, typ `pc-bundle-revocation+jwt`, with `publisher`, `scope` (`KEY` with the `kid`, or `BUNDLE` with the `name` and `max_version`, which revokes that version and every lower one) and `iat`. Post it at the `revocations_url` orgs pinned with your key, one statement per line; PantherClaw fetches it daily, and an org can also submit it at once. Revocation stops the affected installs immediately, and their items stay off (HR-799, HR-800). Then release a fixed, higher version.

Orgs do not depend on you to revoke: an admin can revoke your key or a bundle at any time (R-91).
