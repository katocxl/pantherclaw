-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- M31 credential kinds (G0 M31 D952, D962, HR-721, HR-726). Like the
-- other minted kinds, each is also bound into the seal, so a blob sealed as
-- one kind never opens as another.
-- - google_service_account holds a Google service account's email, RSA
--   key, token endpoint, optional delegated user and scopes; the gateway
--   signs a five-minute assertion per dispatch, exchanges it for an access
--   token and places only that token, as "Authorization: Bearer".
-- - snowflake_keypair holds a Snowflake account, user and RSA key; the
--   gateway signs a key-pair JWT per dispatch and places it as
--   "Authorization: Bearer".

-- +goose Up
ALTER TABLE pc.credentials
    DROP CONSTRAINT credentials_kind,
    ADD CONSTRAINT credentials_kind
        CHECK (kind IN ('static', 'github_app', 'oauth_client', 'aws_sigv4', 'google_service_account', 'snowflake_keypair')) NOT VALID,
    ADD CONSTRAINT credentials_google_service_account_bearer
        CHECK (kind <> 'google_service_account' OR (header = 'Authorization' AND scheme = 'Bearer')) NOT VALID,
    ADD CONSTRAINT credentials_snowflake_keypair_bearer
        CHECK (kind <> 'snowflake_keypair' OR (header = 'Authorization' AND scheme = 'Bearer')) NOT VALID;
-- Every existing row is one of the four earlier kinds, so the scans below
-- find nothing to refuse, and validating blocks neither reads nor writes.
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.credentials VALIDATE CONSTRAINT credentials_kind;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.credentials VALIDATE CONSTRAINT credentials_google_service_account_bearer;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.credentials VALIDATE CONSTRAINT credentials_snowflake_keypair_bearer;

-- +goose Down
ALTER TABLE pc.credentials
    DROP CONSTRAINT credentials_snowflake_keypair_bearer,
    DROP CONSTRAINT credentials_google_service_account_bearer,
    DROP CONSTRAINT credentials_kind,
    ADD CONSTRAINT credentials_kind CHECK (kind IN ('static', 'github_app', 'oauth_client', 'aws_sigv4'));
