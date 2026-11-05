// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds of cross-org federation (G0 M35 D1020..D1024), kept in one
// file: the org's federation keys and endpoint, pairwise trusts, listings
// and cross-org grants. The ledger stores each as "audit." + the kind.
const (
	FederationEndpointSet            = "federation.endpoint_set"
	FederationGrantIssued            = "federation.grant_issued"
	FederationGrantRevoked           = "federation.grant_revoked"
	FederationKeyRetired             = "federation.key_retired"
	FederationKeyRewrapped           = "federation.key_rewrapped"
	FederationKeyRotated             = "federation.key_rotated"
	FederationListingCreated         = "federation.listing_created"
	FederationListingRetired         = "federation.listing_retired"
	FederationPeerRotationUnverified = "federation.peer_rotation_unverified"
	FederationTrustActive            = "federation.trust_active"
	FederationTrustConfirmed         = "federation.trust_confirmed"
	FederationTrustPeerConfirmed     = "federation.trust_peer_confirmed"
	FederationTrustProposed          = "federation.trust_proposed"
	FederationTrustRefreshed         = "federation.trust_refreshed"
	FederationTrustRevoked           = "federation.trust_revoked"
	FederationTrustStale             = "federation.trust_stale"
)
