-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- GitHub App credentials (G0 M8 decision 3, track G slice G3, HR-203,
-- HR-204). A sealed credential gets a kind: static (every credential so
-- far) is placed on a request as sealed; github_app holds an App's id, its
-- installation, the account and the App's private key, which the gateway
-- uses only to sign App JWTs and mint an installation token per authorized
-- action. The kind is also bound into the seal itself, so a blob sealed as
-- one kind never opens as the other. A GitHub App's tokens are placed as
-- "Authorization: Bearer", so its connection must use that header and
-- scheme.

-- +goose Up
ALTER TABLE pc.credentials
    ADD COLUMN kind text NOT NULL DEFAULT 'static',
    ADD CONSTRAINT credentials_kind CHECK (kind IN ('static', 'github_app')),
    ADD CONSTRAINT credentials_github_app_bearer CHECK (kind <> 'github_app' OR (header = 'Authorization' AND scheme = 'Bearer'));

GRANT SELECT (kind) ON pc.credentials TO pc_audit_ro;

-- +goose Down
REVOKE SELECT (kind) ON pc.credentials FROM pc_audit_ro;
ALTER TABLE pc.credentials
    DROP CONSTRAINT credentials_github_app_bearer,
    DROP CONSTRAINT credentials_kind,
    DROP COLUMN kind;
