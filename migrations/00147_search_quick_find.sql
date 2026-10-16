-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Quick find (G0 M11 part 2 coordinator decision D45; F304, F320, HR-295).
--
-- Quick find matches names and titles case-insensitively by prefix or
-- substring with an escaped LIKE on lower(name). These indexes serve the
-- prefix matches (text_pattern_ops); substring matches scan only the rows
-- left after the viewer's scope. No pg_trgm. Exact ids and id prefixes use
-- the primary keys (an id prefix becomes a key range).

-- +goose Up
-- squawk: these tables hold one row per agent, connection, case, incident,
-- alert, package, gateway, service account, automation or person of an org, so building
-- each index locks the table briefly; goose runs each migration in one
-- transaction (.squawk.toml), so CONCURRENTLY is not possible.
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX agents_find_name ON pc.agents (org_id, lower(name) text_pattern_ops);
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX connections_find_name ON pc.connections (org_id, lower(name) text_pattern_ops);
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX cases_find_title ON pc.cases (org_id, lower(title) text_pattern_ops);
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX incidents_find_title ON pc.incidents (org_id, lower(title) text_pattern_ops);
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX alerts_find_title ON pc.alerts (org_id, lower(title) text_pattern_ops);
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX tool_packages_find_name ON pc.tool_packages (org_id, lower(name) text_pattern_ops);
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX gateways_find_name ON pc.gateways (org_id, lower(name) text_pattern_ops);
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX service_accounts_find_name ON pc.service_accounts (org_id, lower(name) text_pattern_ops);
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX users_find_display_name ON pc.users (org_id, lower(display_name) text_pattern_ops);
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX users_find_email ON pc.users (org_id, lower(email) text_pattern_ops);
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX automations_find_name ON pc.automations (org_id, lower(name) text_pattern_ops);

-- +goose Down
DROP INDEX pc.automations_find_name;
DROP INDEX pc.users_find_email;
DROP INDEX pc.users_find_display_name;
DROP INDEX pc.service_accounts_find_name;
DROP INDEX pc.gateways_find_name;
DROP INDEX pc.tool_packages_find_name;
DROP INDEX pc.alerts_find_title;
DROP INDEX pc.incidents_find_title;
DROP INDEX pc.cases_find_title;
DROP INDEX pc.connections_find_name;
DROP INDEX pc.agents_find_name;
