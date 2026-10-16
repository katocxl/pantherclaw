-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Cross-stream reads the M11 part 2 exit wires (G0 M11 part 2 D92, D116).

-- name: ExposedPromotions :many
-- The live promotions (ACTIVE or PROVISIONAL) a person made since a time:
-- a compromised publisher's exposure, reviewed one by one (D43, D116 U1).
SELECT id::text AS item_id,
       ('promotion of ' || operation || ' for agent ' || agent_id::text || ' (' || lower(state) || ')')::text AS label,
       promoted_at AS at
FROM pc.agent_promotions
WHERE org_id = sqlc.arg(org_id) AND promoted_by = sqlc.arg(user_id)
  AND promoted_at >= sqlc.arg(since)::timestamptz AND state IN ('ACTIVE', 'PROVISIONAL')
ORDER BY promoted_at DESC, id
LIMIT 1001;
