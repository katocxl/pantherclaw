-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- M20 credential kinds (G0 M20 D254, HR-524, HR-525). Like github_app,
-- each kind is also bound into the seal, so a blob sealed as one kind never
-- opens as another.
-- - oauth_client holds an OAuth 2.0 client's token endpoint, id, scope and
--   secret; the gateway exchanges it for an access token once per dispatch
--   and places only that token, as "Authorization: Bearer", so its
--   connection must use that header and scheme.
-- - aws_sigv4 holds an AWS base access key that signs only an
--   sts:AssumeRole per dispatch, narrowed and for 15 minutes; the target
--   request is signed with the session's key in a SigV4 Authorization
--   header (scheme AWS4-HMAC-SHA256).

-- +goose Up
ALTER TABLE pc.credentials
    DROP CONSTRAINT credentials_kind,
    ADD CONSTRAINT credentials_kind CHECK (kind IN ('static', 'github_app', 'oauth_client', 'aws_sigv4')),
    ADD CONSTRAINT credentials_oauth_client_bearer CHECK (kind <> 'oauth_client' OR (header = 'Authorization' AND scheme = 'Bearer')),
    ADD CONSTRAINT credentials_aws_sigv4_header CHECK (kind <> 'aws_sigv4' OR (header = 'Authorization' AND scheme = 'AWS4-HMAC-SHA256'));

-- +goose Down
ALTER TABLE pc.credentials
    DROP CONSTRAINT credentials_aws_sigv4_header,
    DROP CONSTRAINT credentials_oauth_client_bearer,
    DROP CONSTRAINT credentials_kind,
    ADD CONSTRAINT credentials_kind CHECK (kind IN ('static', 'github_app'));
