// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package db

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Role names (bootstrap_roles.sql).
const (
	RoleMigrator = "pc_migrator"
	RoleApp      = "pc_app"
	RoleAuditRO  = "pc_audit_ro"
	RoleLister   = "pc_lister"
	// RoleRetention removes expired evidence bodies; only the worker's
	// retention job uses it (G0 M7 design decision 9, HR-198).
	RoleRetention = "pc_retention"
)

var (
	//go:embed bootstrap_roles.sql
	bootstrapRolesSQL string
	//go:embed bootstrap_database.sql
	bootstrapDatabaseSQL string
)

// RolePasswords holds the login passwords set during bootstrap.
type RolePasswords struct {
	Migrator  pclog.Secret[[]byte]
	App       pclog.Secret[[]byte]
	AuditRO   pclog.Secret[[]byte]
	Retention pclog.Secret[[]byte]
}

// bootstrapLockKey serializes concurrent bootstraps of one cluster (taken in
// the database the admin connection uses).
const bootstrapLockKey = 0x70635f626f6f74 // "pc_boot"

// BootstrapRoles creates or updates the cluster-wide roles and sets their
// passwords. It must run with a superuser connection (only superusers can
// grant BYPASSRLS to pc_lister). Passwords are sent as SCRAM-SHA-256
// verifiers, and statement logging is disabled for the transaction, so no
// plaintext password reaches the server or its logs.
func BootstrapRoles(ctx context.Context, admin *pgx.Conn, pw RolePasswords) error {
	logins := map[string]pclog.Secret[[]byte]{
		RoleMigrator: pw.Migrator, RoleApp: pw.App, RoleAuditRO: pw.AuditRO, RoleRetention: pw.Retention,
	}
	for role, p := range logins {
		if err := checkPassword(p.Reveal()); err != nil {
			return fmt.Errorf("db: bootstrap: %s password: %w", role, err)
		}
	}
	return pgx.BeginFunc(ctx, admin, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL log_statement = 'none'"); err != nil {
			return fmt.Errorf("db: bootstrap: %w", err)
		}
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(bootstrapLockKey)); err != nil {
			return fmt.Errorf("db: bootstrap lock: %w", err)
		}
		if _, err := tx.Exec(ctx, bootstrapRolesSQL); err != nil {
			return fmt.Errorf("db: bootstrap roles: %w", err)
		}
		for _, role := range []string{RoleMigrator, RoleApp, RoleAuditRO, RoleRetention} {
			verifier, err := scramVerifier(logins[role].Reveal())
			if err != nil {
				return err
			}
			// format(%I, %L) quotes server-side; the literal is a verifier,
			// not the password.
			var stmt string
			if err := tx.QueryRow(ctx, "SELECT format('ALTER ROLE %I PASSWORD %L', $1::text, $2::text)", role, verifier).Scan(&stmt); err != nil {
				return fmt.Errorf("db: bootstrap: %w", err)
			}
			if _, err := tx.Exec(ctx, stmt); err != nil {
				return fmt.Errorf("db: bootstrap: set %s password: %w", role, err)
			}
		}
		return nil
	})
}

// BootstrapDatabase prepares the database the admin connection is connected
// to: schema pc owned by pc_migrator, minimal grants, no PUBLIC privileges.
func BootstrapDatabase(ctx context.Context, admin *pgx.Conn) error {
	return pgx.BeginFunc(ctx, admin, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, bootstrapDatabaseSQL); err != nil {
			return fmt.Errorf("db: bootstrap database: %w", err)
		}
		return nil
	})
}

// checkPassword requires 24..256 printable ASCII characters, which also
// makes SASLprep normalization a no-op.
func checkPassword(p []byte) error {
	if len(p) < 24 || len(p) > 256 {
		return errors.New("must be 24..256 characters")
	}
	for _, c := range p {
		if c < 0x21 || c > 0x7e {
			return errors.New("must be printable ASCII without spaces")
		}
	}
	return nil
}

const scramIterations = 4096

// scramVerifier returns the PostgreSQL SCRAM-SHA-256 password verifier
// (RFC 5802/7677): SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey>.
func scramVerifier(password []byte) (string, error) {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	return scramVerifierWithSalt(password, salt, scramIterations)
}

func scramVerifierWithSalt(password, salt []byte, iter int) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, string(password), salt, iter, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("db: scram: %w", err)
	}
	clientKey := hmacSHA256(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSHA256(salted, "Server Key")
	b64 := base64.StdEncoding.EncodeToString
	return "SCRAM-SHA-256$" + strconv.Itoa(iter) + ":" + b64(salt) + "$" + b64(storedKey[:]) + ":" + b64(serverKey), nil
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}
