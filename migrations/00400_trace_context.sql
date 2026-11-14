-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The agent's W3C trace context on a transaction (G0 M36 D1060; HR-785).
-- The gateway reads a traceparent header (or an MCP request's
-- params._meta.traceparent) on every face and sends it beside the action;
-- the Authority stores it on the transaction it creates. It is correlation
-- metadata only: never part of the ActionIR, a digest, a receipt or a
-- binding, and an action without one is decided exactly as one with it.
-- The OTLP exporter (00401) reads it to put the transaction's spans in the
-- agent's own trace. Transactions recorded before this migration have
-- none.

-- +goose Up
ALTER TABLE pc.transactions
    ADD COLUMN trace_id       bytea,
    ADD COLUMN parent_span_id bytea,
    ADD COLUMN trace_flags    smallint;
-- The new columns are NULL in every row: the scans find nothing to refuse,
-- and validating blocks neither reads nor writes.
ALTER TABLE pc.transactions
    ADD CONSTRAINT transactions_trace_context
        CHECK ((trace_id IS NULL OR octet_length(trace_id) = 16)
            AND (parent_span_id IS NULL OR octet_length(parent_span_id) = 8)
            AND (trace_flags IS NULL OR trace_flags BETWEEN 0 AND 255)
            AND (trace_id IS NULL) = (parent_span_id IS NULL)
            AND (trace_id IS NULL) = (trace_flags IS NULL)) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.transactions VALIDATE CONSTRAINT transactions_trace_context;

-- +goose Down
ALTER TABLE pc.transactions
    DROP CONSTRAINT transactions_trace_context,
    DROP COLUMN trace_flags,
    DROP COLUMN parent_span_id,
    DROP COLUMN trace_id;
