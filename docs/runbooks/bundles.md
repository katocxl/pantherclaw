# Publisher bundles: pin, install, revoke

How an org uses content from publishers outside the PantherClaw project (G0 M37; [ADR-0064](../adr/0064-publishers-and-bundles.md); HR-795..803). A bundle is data only: tool packages with their OpenAPI specs, detection rules, playbooks, fact provider declarations and channel templates. Nothing in it runs as code, and everything it installs lands as drafts or templates that your org reviews, and signs where it signs its own (founder decisions FQ37-1..3). Publishers follow the [publisher guide](../extensions/publishing.md).

The mechanism is Community edition. Each item kind keeps its own edition: a detection rule needs Business, a playbook (automation) Team, and tool packages keep their usual review and org signing.

## 1. Pin the publisher's key

Get the publisher's key file (`.pub`) and its fingerprint (a lowercase hex SHA-256), and check the fingerprint through a channel you already trust: their own website, a signed release note, a contract. The marketplace only lists what publishers submit and vouches for nobody (T-363, T-364). Compare the publisher id, not the display name.

```bash
pclaw publisher pin --publisher acme-tools --key-file acme-tools.key.pub --fingerprint <hex> \
  [--allowed-kind detection_rule]... [--revocations-url https://acme.example/pantherclaw/revocations]
```

pclaw refuses a key file whose fingerprint differs from `--fingerprint`, and a fingerprint without a key file: a fingerprint alone cannot pin a key. The server computes the fingerprint and key id itself and refuses a mismatch (`PUBLISHER_KEY_FINGERPRINT_MISMATCH`).

This needs `publisher.manage` (Security Admin or Org Admin, a person). The pin starts PENDING and trusts nothing yet. pclaw prints a confirm link, `<server URL>/integrations/publisher-pins/<id>/confirm`: open it and confirm with your security key. Only then is the pin ACTIVE (HR-795). `ActivatePublisherPin` over the API always answers that a step-up is needed.

A pin can name the kinds it allows (none named means all) and a `revocations_url` where the publisher posts signed revocation statements (https). `ListPublisherPins` and `GetPublisherPin` (`bundle.read`) show pins.

## 2. Install a bundle

```bash
pclaw bundle verify ext.acme-tools.starter-1.0.0.pcbundle --public-key acme-tools.key.pub --fingerprint <hex>   # offline, optional
pclaw bundle install ext.acme-tools.starter-1.0.0.pcbundle
```

This needs `bundle.install` (Org Admin or Security Admin), signed in as yourself. One upload carries a `.pcbundle` file of at most 960 KiB. The server refuses the bundle unless (HR-796, HR-797):

- it decodes strictly: the closed list of kinds, text item files only under `items/`, at most 64 items, 1 MiB per item and 8 MiB uncompressed in all, no executables or symlinks;
- its signature verifies with an ACTIVE pin of that publisher, and every item's kind is allowed by the pin;
- every item's SHA-256 matches the manifest and every name is in `ext.<publisher>.…`;
- its version is not lower than the highest installed (ROLLBACK), and the same version comes as the same file (EQUIVOCATION; the same file again is `BUNDLE_ALREADY_INSTALLED`).

What an install creates (HR-798), none of it active:

| Item | Becomes | What you do next |
|---|---|---|
| `tool_package` (+ `openapi_spec`) | a DRAFT tool package, like the OpenAPI importer's | review it and sign it with an org package key, then import it: an `ext.` package imports only when it matches a DRAFTED install item of the same name, version and SHA-256 (`BUNDLE_ITEM_MISMATCH` otherwise) |
| `detection_rule` | a DRAFT custom rule | test it and publish it with the two-person confirm |
| `playbook` | a DRAFT automation named after the item, dots and underscores as dashes (`ext.acme-tools.contain` → `ext-acme-tools-contain`); a name already taken fails the install (`BUNDLE_AUTOMATION_NAME_TAKEN`) | validate, simulate and enable it as usual |
| `facts_declaration` | a TEMPLATE record | register a provider through the existing flow if you want one |
| `channel_template` | a TEMPLATE record | create the channel and its secrets yourself (HR-801) |

`ListBundleInstalls` and `GetBundleInstall` (`bundle.read`: also Auditors) show each install, its items and what they became. Audit kinds: `bundle.installed`, `bundle.install_failed`.

## 3. Revoke

- **A bundle:** `RevokeBundleInstall` revokes that install and every install of the same bundle at that version or lower.
- **A key:** `RevokePublisherPin` with reason UNPINNED stops trusting the key for new installs and leaves existing installs as they are; COMPROMISED also revokes every install the key signed.
- **The publisher says so:** a revocation statement signed by any key of that publisher your org has ever pinned, sent with `SubmitRevocation` or fetched daily from the pin's `revocations_url` (https, one statement per line, 64 KiB at most, no redirects). A KEY statement revokes like COMPROMISED; a BUNDLE statement revokes that bundle up to its `max_version`. An admin needs no statement (HR-800).

Revocation acts at once, in one transaction (HR-799): the installs and their items turn REVOKED, their tool package versions are quarantined so calls refuse or hold as for a compromised org key, their custom rules are disabled and their automations paused. Admins and Security Admins get a `bundle.revoked` notification, and the built-in detection `pc.bundles.revoked` raises a HIGH alert (alert only). A revoked item stays off: enabling, activating or resuming its automation, or publishing or confirming its custom rule, is refused with `BUNDLE_REVOKED`.

To resume, install a higher version that is not revoked, then review and sign it as before.

A publisher's `revocations_url` may stop answering, so revocation also relies on your org (R-91): watch the publisher's own channels and revoke yourself when needed.
