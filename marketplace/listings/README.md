# Marketplace listings

Each publisher submits one file here, `<publisher>.json`, through a reviewed pull request. `task marketplace:build` turns the listings (and, optionally, a Hub build directory) into the static pages in `dist/marketplace` (G0 M37 D1085; HR-802).

A listing is not an endorsement. The marketplace lists what publishers submit, takes no payment and has no install button; an org installs a publisher's bundle only after it pinned that publisher's key and confirmed the pin with a security key ([publisher guide](../../docs/extensions/publishing.md)).

```json
{
  "publisher": "example",
  "display_name": "Example Publisher",
  "homepage": "https://example.com/pantherclaw",
  "key_fingerprints": ["<lowercase hex SHA-256 of the raw Ed25519 public key>"],
  "bundles": [
    {
      "name": "ext.example.starter",
      "version": "1.0.0",
      "url": "https://example.com/bundles/ext.example.starter-1.0.0.pcbundle",
      "sha256": "<lowercase hex SHA-256 of the .pcbundle file>",
      "summary": "One detection rule, one playbook and one OpenAPI tool package."
    }
  ]
}
```

Rules the build checks (unknown fields are refused):

- `publisher` matches `^[a-z][a-z0-9-]{2,31}$` and is the file name.
- `homepage` and each bundle `url` are https URLs without credentials.
- `key_fingerprints` holds 1 to 16 lowercase hex SHA-256 values, as `pclaw publisher key create` prints them.
- Each bundle is named `ext.<publisher>.<name>`, has a semver version and the SHA-256 of the exact `.pcbundle` file, and is listed once per version.

Reviewers check that a new publisher id does not imitate an existing one (T-363) and that the fingerprints match what the publisher's own homepage states. The build proves nothing about a publisher: each org checks the fingerprint itself when it pins the key.
