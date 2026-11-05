# Connector breadth: Google Workspace, Microsoft 365, SaaS, model clouds, Snowflake and drafted packages

**Milestone:** M31 (G0 M31 D950–D963, D1002; [ADR-0058](../adr/0058-connector-breadth-and-openapi-importer.md)). **Audience:** an Org Admin connecting these services, or turning an OpenAPI spec into a package.

Agents reach these services through packages the gateway decides like any other action. PantherClaw holds every key and places only a token minted for one dispatch; the agent holds none of them.

| Package | Credential | Operations |
|---|---|---|
| `pc.gmail` | Google service account | `gmail.message.send`, `.list`, `.get` |
| `pc.google-workspace` | Google service account | `drive.file.list`, `.get`, `drive.permission.create`, `.delete`, `calendar.event.list`, `.create` |
| `pc.m365` | OAuth client (Microsoft) | `m365.mail.send`, `.list`, `m365.drive.item.list`, `.invite`, `.create_link` |
| `pc.salesforce` | OAuth client (Salesforce) | `salesforce.record.get`, `salesforce.report.run`, `salesforce.limits.read` |
| `pc.notion`, `pc.linear` | API key | Notion pages, search and blocks; Linear issues and comments (fixed GraphQL documents) |
| `pc.bedrock`, `pc.vertex` | AWS signing (Bedrock), Google service account (Vertex) | Anthropic models, checked like model connections (M29) |
| `pc.snowflake` | Snowflake key pair | allow-listed reads over the SQL API |

## Google: seal a service account for one mailbox

Create the service account in Google Cloud, grant it domain-wide delegation for the scopes you need in the Workspace admin console, and download its JSON key. Seal it with the one user it acts as:

```bash
pclaw seal --connection <connection id> --google-service-account key.json \
  --subject ops@example.com --scope https://www.googleapis.com/auth/gmail.send
```

The connection's allowed hosts must include `oauth2.googleapis.com` and the API host (`gmail.googleapis.com`, `www.googleapis.com`). The gateway signs a five-minute assertion per dispatch and exchanges it for one token; nothing is cached. A call that names another mailbox than `--subject` is refused before anything is minted (`TARGET_NOT_CREDENTIAL_SUBJECT`). Delegation itself is granted in Google, so keep its scopes to what the packages need (residual risk R-75).

## Microsoft 365 and Salesforce: token endpoints from a closed list

An OAuth client's token endpoint must be one of:

- `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`, the tenant a GUID (either case) or a domain;
- `https://<my domain>.my.salesforce.com/services/oauth2/token`.

Anything else is refused when sealed (`not a known provider`) and when opened. Use app-only permissions (Microsoft) or a connected app with the client-credentials flow (Salesforce):

```bash
pclaw seal --connection <connection id> --from-file client.secret \
  --oauth-token-url https://acme.my.salesforce.com/services/oauth2/token \
  --oauth-client-id <consumer key> --oauth-scope api
```

## Shares wait for a person when they leave the organization

`drive.permission.create`, `m365.drive.item.invite` and `m365.drive.item.create_link` name their destinations. A share to anyone, or an anonymous link, holds with `SHARE_PUBLIC`; a share to a user, group or domain the organization has not listed holds with `SHARE_ACCOUNT_NOT_OWNED`. List your own domains first (M30):

```bash
pclaw org accounts add email_domain example.com --reason "our Workspace domain"
```

Mail sends, Drive shares and Microsoft 365 invites and links are irreversible. They are never retried; if the gateway can't tell whether one happened, the transaction waits for reconciliation instead of being sent again.

## Snowflake

Create the connection with `--snowflake-account`, `--snowflake-warehouse`, `--snowflake-database` and `--snowflake-schema`, then seal the user's unencrypted RSA key (PKCS#8 PEM):

```bash
pclaw seal --connection <connection id> --snowflake-account ACME-PROD --snowflake-user PC_READER --from-file reader.p8
```

Reads are built from the package's allow-list with typed binds; a key-pair JWT is signed per dispatch.

## Drafting a package from an OpenAPI spec

```bash
pclaw package draft openapi spec.yaml --name acme.widgets --version 0.1.0 --out acme-widgets.yaml
```

The draft starts with `review_required`, and every place a person must decide is marked `# review:` (targets, units, extraction). The importer refuses Swagger 2, external `$ref`s, `$ref` chains deeper than 16, and names starting `pc.`. Writes are drafted as irreversible with every param in the approval.

Importing the draft as it is fails with `DRAFT_NOT_REVIEWED`. Review it, delete the `review_required` line, then sign and import it with your org's package key:

```bash
pclaw package sign --key org.key.json --version 1 --expires-days 90 --out targets.json acme-widgets.yaml
pclaw package import --name acme.widgets --version 0.1.0 --targets-file targets.json --file acme-widgets.yaml
```

Test it against `pantherclaw-sim openapi --spec spec.yaml`, which answers each operation with its first example.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `DRAFT_NOT_REVIEWED` on import | `review_required` is still in the file |
| `not a known provider` when sealing | the token endpoint is not Microsoft's, Salesforce's or a loopback simulator's |
| `TARGET_NOT_CREDENTIAL_SUBJECT` | the agent named a mailbox other than the sealed subject |
| a send refused with a header error | a subject or recipient carried a line break or separator |
| a share held | the destination is public or outside your owned accounts |
