// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M20 webhook key permissions (G0 M20 D261): the org's Ed25519 `webhooks`
// key that signs opted-in webhooks (HR-510..512).
//
//   - webhook_key.read: list the org's ACTIVE and RETIRING webhook keys
//     (public halves only). Org Admin, Security Admin and Auditor hold it.
//   - webhook_key.manage: rotate the key, with a step-up. Org Admin and
//     Security Admin hold it. Org Admin stays bindable to service
//     accounts, so it is not in humanOnly: the step-up refuses any caller
//     but a person.
const (
	PermWebhookKeyRead   Permission = "webhook_key.read"
	PermWebhookKeyManage Permission = "webhook_key.manage"
)

// m20WebhooksCatalog are the M20 webhook key permissions in catalog order.
var m20WebhooksCatalog = []Permission{PermWebhookKeyRead, PermWebhookKeyManage}

func init() {
	catalog = append(catalog, m20WebhooksCatalog...)
	for i := range roles {
		r := &roles[i]
		switch r.Name {
		case RoleOrgAdmin, RoleSecurityAdmin:
			r.Permissions = append(r.Permissions, PermWebhookKeyRead, PermWebhookKeyManage)
			r.Description += " Reads and rotates the org's webhook signing key (with a security key)."
		case RoleAuditor:
			r.Permissions = append(r.Permissions, PermWebhookKeyRead)
			r.Description += " Reads the org's webhook signing keys."
		}
	}
}
