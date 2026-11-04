-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- A gateway's Kubernetes binding (G0 M32 D968): the cluster, namespace,
-- service account (name and UID) and optional image digests whose
-- projected token (audience pantherclaw-gateway:<org>) may enroll a
-- replica of the gateway instead of a `pcg_` token. NULL: no binding, so
-- only enrollment tokens work. Setting or clearing it needs gateway.manage
-- and is audited (gateway.kubernetes_binding_set / _cleared). Its shape
-- ({"cluster","namespace","service_account_name","service_account_uid",
-- "image_digests"}) is checked in Go.

-- +goose Up
-- The new column is NULL in every row, so the check holds at once; gateways
-- is a small table.
ALTER TABLE pc.gateways
    ADD COLUMN kube_binding jsonb,
    -- squawk-ignore constraint-missing-not-valid
    ADD CONSTRAINT gateways_kube_binding CHECK (kube_binding IS NULL OR (jsonb_typeof(kube_binding) = 'object'
        AND octet_length(kube_binding::text) <= 8192));
GRANT UPDATE (kube_binding) ON pc.gateways TO pc_app;

-- +goose Down
REVOKE UPDATE (kube_binding) ON pc.gateways FROM pc_app;
ALTER TABLE pc.gateways DROP COLUMN kube_binding;
