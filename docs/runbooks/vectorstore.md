# Vector-store connector (pgvector)

**Milestone:** M30 ([G0 M30](../g0/M30.md) D922–D927; [ADR-0057](../adr/0057-firewall-gaps-from-the-threat-map.md)). **Audience:** a Gateway Admin (`connection.manage`) connecting a retrieval store, and the people who write grants for agents that read or write it. Edition: as `pc-postgres`. Runtime firewall.

`pc.vectorstore` gives agents three operations on one pgvector table: `vector_query` (a read), `vector_upsert` and `vector_delete` (reversible writes). Agents never send SQL. The gateway builds parameterised SQL, quotes identifiers itself and never runs DDL on your database (HR-704).

## 1. Create the table

The table has a fixed layout. Print it for the connection and run it yourself as the table's owner:

```bash
pclaw connection vectorstore ddl <connection-id>
```

It prints `CREATE EXTENSION IF NOT EXISTS vector` and a table with `id`, `content`, `embedding vector(<dimensions>)`, `metadata jsonb` and the provenance columns `pc_run_id`, `pc_agent_id`, `pc_transaction_id` and `pc_written_at`. Grant the connection's role SELECT, INSERT, UPDATE and DELETE on that table only. The role must not be a superuser: the connection test refuses it (HR-705).

## 2. Create the connection

```bash
pclaw connection create kb --kind vectorstore --gateway <gw> --package pc.vectorstore --access pantherclaw_held \
  --db-host db.internal.example --db-port 5432 --db-name kb --db-user pc_kb --sslmode verify-full \
  --vector-schema public --vector-table docs --dimensions 1536 --distance cosine \
  --writer <agent-id>
```

- `--sslmode require` is accepted only with `--internal` and `--ca-file`, as for a Postgres connection.
- **The endpoint is fixed after create.** Host, port, database, user, sslmode, CA and `--internal` cannot change; an update that changes them is refused `VECTORSTORE_ENDPOINT_IMMUTABLE`. To move the store, create a new connection.
- Schema, table, dimensions, distance and writers can change with `pclaw connection update` (`--clear-writers` empties the list).

## 3. Writers and holds

- An upsert or delete by an agent on the writer list (at most 64) runs as granted.
- An upsert or delete by any other agent **waits for a person** (`VECTOR_WRITE_NOT_WRITER`). An empty list holds every write.
- Every entry records the run, agent and transaction that wrote it. They come only from the gateway's verified permit, never from the agent's arguments; a write whose permit lacks them is refused `CANNOT_AUTHORIZE`.
- A query returns the provenance with every entry, so a reader can see who wrote what it retrieves.

## 4. Bounds

| Param | Limit |
|---|---|
| `embedding` | 1 to 16000 numbers, all finite |
| `top_k` | 1 to 100, default 10 |
| `content` | at most 8 KiB |
| `filter` | a flat string map, at most 16 keys |
| `metadata` | a flat string map, at most 32 keys |

Map keys match `^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`, values are at most 1 KiB, and a map is at most 8 KiB in all. Embeddings and maps are bound by the gateway and hidden from policy. Content signals scan `content`, map values and query results in the organization's mode.

**Known limit (open in the testing phase).** A tool call's embedding is a JSON number array, and the action format refuses JSON numbers in params (HR-101). Until that is settled, `vector_query` and `vector_upsert` from an MCP or HTTP tool call are refused before a decision.

## 5. When something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| The connection test reports a superuser | The role is a superuser | Use a role with table privileges only |
| The connection test reports the extension missing | `vector` is not installed | Run the DDL from §1 |
| Writes wait for approval | The agent is not on the writer list | Add it with `--writer`, or approve each write |
| An update is refused `VECTORSTORE_ENDPOINT_IMMUTABLE` | The update changes the endpoint | Create a new connection |
