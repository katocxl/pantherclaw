# Publisher bundles: pin, install, revoke

How an org uses content from publishers outside the PantherClaw project (G0 M37; [ADR-0064](../adr/0064-publishers-and-bundles.md); HR-795..803). A bundle is data only: tool packages with their OpenAPI specs, detection rules, playbooks, fact provider declarations and channel templates. Nothing in it runs as code, and everything it installs lands as drafts that your org reviews and signs (founder decisions FQ37-1..3). Publishers follow the [publisher guide](../extensions/publishing.md).

The mechanism is Community edition. Each item kind keeps its own edition: a detection rule needs Business, a playbook (automation) Team, and tool packages keep their usual review and org signing.

## 1. Pin the publisher's key

Get the publisher's key fingerprint (a lowercase hex SHA-256) through a channel you already trust: their own website, a signed release note, a contract. The marketplace only lists what publishers submit and vouches for nobody (T-363, T-364). Compare the publisher id, not the display name.

```bash
pclaw publisher pin --publisher acme-tools --fingerprint <hex>
# or, with the public key file the publisher gave you:
pclaw publisher pin --publisher acme-tools --key-file acme-tools.pub
```

This needs `publisher.manage` (Security Admin or Org Admin, a person). The pin starts PENDING and trusts nothing yet. pclaw prints a confirm link, `<server URL>/integrations/publisher-pins/<id>/confirm`: open it and confirm with your security key. Only then is the pin ACTIVE (HR-795). `ActivatePublisherPin` over the API always answers that a step-up is needed.

A pin can name the kinds it allows (empty means all) and a `revocations_url` where the publisher posts signed revocation statements (https).

## 2. Install a bundle

```bash
pclaw bundle verify ext.acme-tools.starter-1.0.0.pcbundle --fingerprint <hex>   # offline, optional
pclaw bundle install ext.acme-tools.starter-1.0.0.pcbundle
```

This needs `bundle.install` (Org Admin or Security Admin), signed in as yourself. The server refuses the bundle unless (HR-796, HR-797):

- it decodes strictly: the closed list of kinds, paths only under `items/`, at most 64 items, 1 MiB per item and 8 MiB in all, no executables or symlinks;
- its signature verifies with an ACTIVE pin of that publisher, and every item's kind is allowed by the pin;
- every item's SHA-256 matches the manifest and every name is in `ext.<publisher>.…`;
- its version is not lower than the highest installed (ROLLBACK), and the same version has the same digest (EQUIVOCATION).

What an install creates (HR-798), none of it active:

| Item | Becomes | What you do next |
|---|---|---|
| `tool_package` (+ `openapi_spec`) | a DRAFT tool package, like the OpenAPI importer's | review it and sign it with an org package key |
| `detection_rule` | a DRAFT custom rule | test it and publish it with the two-person confirm |
| `playbook` | a DRAFT automation | validate, simulate and enable it as usual |
| `facts_declaration` | a DRAFT provider declaration, or a TEMPLATE record | review it |
| `channel_template` | a TEMPLATE record | create the channel and its secrets yourself (HR-801) |

`ListBundleInstalls` and `GetBundleInstall` (`bundle.read`: also Auditors) show each install, its items and what they became. Audit kinds: `bundle.installed`, `bundle.install_failed`.

## 3. Revoke

- **A bundle:** `RevokeBundleInstall`.
- **A key:** `RevokePublisherPin` with reason UNPINNED or COMPROMISED; revoking a pin also revokes every install signed by that key.
- **The publisher says so:** a revocation statement signed by any key of that publisher your org has pinned, sent with `SubmitRevocation` or fetched daily from the pin's `revocations_url` (https, 64 KiB at most, no redirects). An admin needs no statement (HR-800).

Revocation acts at once, in one transaction (HR-799): the installs and their items turn REVOKED, their tool package versions are quarantined so calls refuse or hold as for a compromised org key, their custom rules are disabled and their automations paused. Admins and Security Admins get a `bundle.revoked` notification, and the built-in detection `pc.bundles.revoked` raises a HIGH alert (alert only).

To resume, install a higher version that is not revoked, then review and sign it as before.

A publisher's `revocations_url` may stop answering, so revocation also relies on your org (R-91): watch the publisher's own channels and revoke yourself when needed.
