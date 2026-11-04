-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Opt-in prompt capture per model connection (G0 M30 D945b; founder answer
-- P). Off by default: a model connection's prompts and replies are captured
-- only while capture_prompts is on, and then only as a capture profile that
-- covers the connection asks, kept for that profile's retention. Turning it
-- on is a protected change a second person confirms with a security key
-- (Business); turning it off applies at once. The model kind store writes
-- it with the rest of the connection's model settings (00330 grants UPDATE
-- by column, so the new column joins them).

-- +goose Up
ALTER TABLE pc.model_connections ADD COLUMN capture_prompts boolean NOT NULL DEFAULT false;
GRANT UPDATE (capture_prompts) ON pc.model_connections TO pc_app;

-- +goose Down
REVOKE UPDATE (capture_prompts) ON pc.model_connections FROM pc_app;
ALTER TABLE pc.model_connections DROP COLUMN capture_prompts;
