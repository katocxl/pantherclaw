-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The nonce cache of agent request signatures (G0 M39 D1123; HR-838). An
-- RFC 9421 signature (Web Bot Auth, Visa Trusted Agent Protocol) is valid
-- for at most 480 seconds and carries a nonce; a nonce is accepted once per
-- agent directory anchor. A row is kept 10 minutes, longer than any
-- signature's window, and pruned by the verifier before each insert.

-- +goose Up
CREATE TABLE pc.payment_sig_nonces (
    org_id    uuid        NOT NULL,
    anchor_id uuid        NOT NULL,
    nonce     text        NOT NULL CHECK (char_length(nonce) BETWEEN 1 AND 256),
    seen_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, anchor_id, nonce),
    FOREIGN KEY (org_id, anchor_id) REFERENCES pc.payment_trust_anchors (org_id, id)
);
CREATE INDEX payment_sig_nonces_seen ON pc.payment_sig_nonces (org_id, seen_at);

ALTER TABLE pc.payment_sig_nonces ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.payment_sig_nonces FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.payment_sig_nonces
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT, DELETE ON pc.payment_sig_nonces TO pc_app;

-- +goose Down
DROP TABLE pc.payment_sig_nonces;
