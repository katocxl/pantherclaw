// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/credentials/app"
	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// TestHR721_MintedM31CredentialsArePlacedOnlyAsBearer: a Google service
// account and a Snowflake key pair are stored with their kind when placed
// as Authorization: Bearer; another header or scheme is refused by the
// service and again by the table (migration 00351).
//
// Covers: HR-721, HR-726
func TestHR721_MintedM31CredentialsArePlacedOnlyAsBearer(t *testing.T) {
	for _, kind := range []string{domain.KindGoogleServiceAccount, domain.KindSnowflakeKeypair} {
		e := newEnv(t)
		_, in := e.seal(t, `{"v":1}`)
		in.Kind, in.Header, in.Scheme = kind, "X-Api-Key", ""
		if _, err := e.svc.PutCredential(e.sealer, in); !is(err, app.ErrKind) {
			t.Fatalf("%s as X-Api-Key: %v", kind, err)
		}
		_, in = e.seal(t, `{"v":1}`)
		in.Kind, in.Header, in.Scheme = kind, "Authorization", "Bearer"
		m, err := e.svc.PutCredential(e.sealer, in)
		if err != nil || m.Kind != kind {
			t.Fatalf("%s: %+v %v", kind, m, err)
		}
		err = e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, "UPDATE pc.credentials SET header = 'X-Api-Key', scheme = NULL WHERE connection_id = $1", e.conn.ID)
			return err
		})
		if err == nil {
			t.Fatalf("the table stored a %s credential outside Authorization: Bearer", kind)
		}
	}
}
