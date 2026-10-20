# Postgres query connector and data scoping

**Milestone:** M14 ([G0 M14](../g0/M14.md) D11, D15–D21; [ADR-0028](../adr/0028-business-connectors-and-data-scoping.md)). **Audience:** a Gateway Admin (`connection.manage`) connecting a database, and the people who write grants and policies for reads. Command flags below follow the brief; the M14 exit status records any change.

`pc.postgres` 1.0.0 gives agents **structured, read-only** access to tables an administrator lists. Agents never send SQL: the gateway builds parameterised SQL from the decided request and the connection's manifest (HR-307), runs it in a read-only transaction that always rolls back (HR-308), and applies the data scope of the decision (HR-310..312). Joins, views and JSON columns are not supported (R-44).

## 1. Prepare the database role

Create a role for PantherClaw that can only read the tables you will list:

```sql
CREATE ROLE pantherclaw_reader LOGIN PASSWORD '<generated>';
GRANT USAGE ON SCHEMA shop TO pantherclaw_reader;
GRANT SELECT ON shop.customers, shop.orders TO pantherclaw_reader;
ALTER ROLE pantherclaw_reader SET default_transaction_read_only = on;
```

The connection test (§4) refuses the connection if the role is a superuser, a member of `pg_write_all_data`, or has INSERT, UPDATE, DELETE or TRUNCATE on any listed table (HR-309). PostgreSQL 13 or later.

## 2. Write the manifest

The manifest is part of the connection's `PostgresConfig`. Only what it lists exists for agents.

| Field | Meaning | Default and limit |
|---|---|---|
| `host`, `port`, `database`, `user` | Where to connect | — |
| `sslmode` | `verify-full` (required); `require` only with `internal` and a pinned CA | — |
| `ca_pem` | Optional pinned CA | at most 16 KiB |
| `internal` | Allows private addresses; setting it needs a step-up, and it is accepted only on a connection served by a customer-hosted gateway whose operator allow-list includes the target's private prefix (loopback and link-local only when listed). Moving the connection to another gateway re-checks this | false |
| `tables[]` | `schema`, `name`, optional `scope_key` and `scope_column` (record scope), optional `max_rows`, `columns[]` of `{name, type, class}` | 1 to 64 tables, 1 to 128 columns each |
| `max_rows` | Row cap per query | 200, at most 1000 |
| `statement_timeout_ms` | Query timeout | 5000, at most 30000 |
| `max_result_bytes` | Answer cap | 1 MiB, at most 4 MiB |
| `min_group_size` | Smallest aggregate group returned | 5, at least 2 |

- Identifiers match `^[a-z_][a-z0-9_]{0,62}$` (no quoted identifiers).
- Only ordinary and partitioned tables (every partition an ordinary table) may be listed; views, materialized views and foreign tables are refused.
- Column types: `text int bigint numeric bool date timestamptz uuid` (no json, jsonb, bytea or arrays).
- Classes: `public`, `internal`, `pii`, `secret`. A `secret` column is never returned to an agent.

Example (one table):

```json
{"schema": "shop", "name": "customers", "scope_key": "customer", "scope_column": "id",
 "columns": [{"name": "id", "type": "uuid", "class": "internal"},
             {"name": "name", "type": "text", "class": "pii"},
             {"name": "email", "type": "text", "class": "pii"},
             {"name": "tier", "type": "text", "class": "public"},
             {"name": "ssn", "type": "text", "class": "secret"}]}
```

Every manifest change is audited. A widening change (a new table or column, a lowered class, a raised limit) needs a security-key step-up.

## 3. Connect

```bash
pclaw connection create shopdb --kind postgres --gateway <gateway id> --package pc.postgres \
  --access pantherclaw_held --config postgres.json --default-mode enforce
pclaw seal --connection <connection id> --from-file db-password.txt --fingerprint <broker key fingerprint>
```

The password is a sealed static credential with no header binding; only the gateway's Postgres client opens it, inside a dispatch. Delete the file afterwards. The gateway applies the same dial-time egress checks as for HTTP connections; private addresses are reachable only with `internal`.

**Confirm the manifest.** The new connection's manifest is only proposed, and the connection cannot dispatch until a person holding `connection.manage` (Gateway Admin) confirms it (Org Admin does not hold that permission): open the confirmation page the create command prints, check the tables, columns, classes, limits and `internal`, and confirm with your security key. Later updates that narrow the manifest apply at once; a widening (a new table or column, a lowered class, a raised limit, `internal` turned on, or any change to a table's `scope_key` or `scope_column`) stays proposed until confirmed on the same page, and the current manifest keeps serving meanwhile. Rolling back migration 00151 refuses while header-less (Postgres) credentials exist; delete those connections first.

## 4. Test the connection

```bash
pclaw connection test <connection id>
```

The test connects with the sealed credential and fails (and the connection cannot dispatch) on a write-capable role, a missing column or a column of another type. Run it again after every manifest or role change.

## 5. What agents can call

| Operation | MCP tool (`/mcp/{conn}`) | HTTP face | Parameters |
|---|---|---|---|
| `postgres.rows.read` | `query_rows` | `POST /{conn}/v1/query` | target `schema.table`; `columns`, `filters` (`query_filter`), `order_by` (`col:asc|desc`), `limit` |
| `postgres.rows.aggregate` | `aggregate_rows` | `POST /{conn}/v1/aggregate` | `group_by`, `measures` (`count|sum|avg|min|max` over a column or `*`), `filters`, `limit` |
| `postgres.tables.read` | `describe_tables` | `GET /{conn}/v1/tables` | target `pg_database` (the connection's database name); returns the tables and columns the agent may see |

Filters are a list of at most 20 predicates `{column, op, value | values}` with ops `eq ne lt le gt ge in is_null not_null prefix`. The SDK and hook faces refuse Postgres connections (`use_gateway_face`). Answers are `{"columns": [...], "rows": [[...]], "truncated": bool, "redacted": n}`. Every value is cut to 4096 characters in SQL (flagged `truncated_values`), and sorting uses the real column type.

Aggregate measures are limited by column (HR-312): `count` on any non-secret column (it returns a number, never a value); `min` and `max` only on numeric, date and timestamptz columns of class public or internal; `sum` and `avg` only on numeric columns; no other measure on pii, secret or text columns. Groups smaller than `min_group_size` are left out.

Every query runs under `REPEATABLE READ READ ONLY` with the statement timeout, a 1 s lock timeout and an idle timeout, then `ROLLBACK`. A query over the time limit is FAILED and does not hang.

## 6. Data scoping (Team)

Scope narrows what an allowed read returns. It is set on grants (per operation) and by policy rules, and only narrows:
- **Records:** `Scope.Records {key, values}`, for example `customer` = the ticket's customer id (at most 100 exact ids). The gateway adds `AND <scope_column> = ANY(...)` on the table whose `scope_key` matches. A table without that scope key gives `CANNOT_AUTHORIZE` `SCOPE_UNSUPPORTED` before any query.
- **Classes:** `Scope.Classes` over `public`, `internal`, `pii`. Values of other classes come back as `"[redacted:<class>]"`; `secret` is always withheld.
- **Columns:** the requested columns are checked against the grant's column values; an extra column is a DENY. Filter, sort and group columns must also be readable (`COLUMN_NOT_ALLOWED`).
- Policy rules `record_scope` and `data_classes` tighten further.
- Aggregate groups smaller than `min_group_size` are left out (HR-312).

Scope works only where the gateway sees the answer (R-42). On SDK, hook and AuthZEN routes or agent-held connections, a decision with a scope obligation is `CANNOT_AUTHORIZE` `SCOPE_UNSUPPORTED`. HTTP connections can be scoped too when their definitions declare `Response.fields` classes; an answer the gateway cannot parse under an obligation is withheld (`SCOPE_UNENFORCEABLE`). Receipts record counts only (rows, values redacted, scope key), never the values.

**Customer-support template.** `pclaw template apply customer-support --agent <agent> --customer <id>` (`--agent` required, because the Postgres rules apply per agent; `--customer` repeatable and required) scopes `postgres.rows.read` to those customers, allows classes public and internal, caps reads at 50 rows and forbids aggregates. A per-ticket agent can be narrowed further with a delegated grant.

## 7. Development

```bash
pantherclaw-server dev seed --postgres <file with the DSN>
```

The fixture schema (`shop.customers`, `shop.orders`, `support.tickets`, a read-only role and a write-capable role) is used two ways. `TestE2E_M14_DataScoping` runs on the Community end-to-end stack against a TLS Postgres target (test CA) behind a customer-hosted gateway, with a confirmed manifest: columns, row caps, `secret`, writes, the connection test, timeouts and the MCP and HTTP faces. Record scope and class redaction (Team) run in in-process Team integration tests with the real Authority and the gateway scope engine. A simulated Postgres connection must target a loopback address and pass a handshake: a read-only `SELECT kind, connection FROM pantherclaw_sim.handshake` must return `postgres` and the connection id. Range scenarios RT-042..RT-044 cover injection, scope escape and write attempts.

## 8. Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| Connection test FAILED: write privilege | The role can write a listed table | Revoke the privilege or use a read-only role |
| `COLUMN_NOT_ALLOWED` | A filter, sort or group column the agent may not read | Use a readable column, or widen the grant deliberately |
| `SCOPE_UNSUPPORTED` | The table has no matching `scope_key`, or the route cannot enforce scope | Add the scope key to the manifest (step-up) or use the gateway face |
| `truncated: true` | The row cap was reached | Narrow the filter; raising `max_rows` is a widening change |
| FAILED after the timeout | The query exceeded `statement_timeout_ms` | Add a filter or an index |
| The connection cannot dispatch after create or a widening update | The manifest (or the widening) is still proposed | Confirm it on the confirmation page with a security key |
| `TARGET_MISMATCH` on `describe_tables` | The `pg_database` target is not the connection's database | Use the connection's database name |
| `KIND_CONFIG_MISSING` | The gateway has no Postgres configuration for the connection | Check the connection on the server; reload the gateway configuration |
