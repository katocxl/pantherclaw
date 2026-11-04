// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestHR660_OnlyTheDispatchsOwnCredentialIsNoted: a dispatch notes the
// credential of its own connection, opened or kept with a pool it reuses,
// and nothing of another connection or outside a dispatch.
// Covers: F952
func TestHR660_OnlyTheDispatchsOwnCredentialIsNoted(t *testing.T) {
	conn := &control.Connection{
		GatewayConnection: &pb.GatewayConnection{Id: "c-1"},
		Credential:        &pb.SealedCredential{Id: "0194f1a0-0000-7000-8000-000000000001", Version: 3},
	}
	if credentialUsed(context.Background()) != nil {
		t.Fatal("outside a dispatch")
	}
	usedCredential(context.Background(), conn) // outside a dispatch: nothing to note, no panic

	ctx := withCredentialUse(context.Background(), conn)
	if u := credentialUsed(ctx); u != nil {
		t.Fatalf("nothing used yet: %v", u)
	}
	usedCredentialVersion(ctx, "c-2", "0194f1a0-0000-7000-8000-000000000002", 1)
	usedCredentialVersion(ctx, "c-1", "", 1)
	if u := credentialUsed(ctx); u != nil {
		t.Fatalf("another connection's, or no credential: %v", u)
	}
	// A pool kept with the credential it was opened with.
	usedCredentialVersion(ctx, "c-1", "0194f1a0-0000-7000-8000-000000000001", 2)
	if u := credentialUsed(ctx); u.GetCredentialId() != "0194f1a0-0000-7000-8000-000000000001" || u.GetVersion() != 2 {
		t.Fatalf("a reused pool's credential: %v", u)
	}
	usedCredential(ctx, conn)
	if u := credentialUsed(ctx); u.GetCredentialId() != conn.Credential.GetId() || u.GetVersion() != 3 {
		t.Fatalf("an opened credential: %v", u)
	}
}
