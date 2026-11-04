// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"errors"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
)

// CodeTargetNotCredentialSubject refuses a subject_target dispatch whose
// target is not the user the connection's Google service account acts as,
// before anything is minted or sent (G0 M31 D956a).
const CodeTargetNotCredentialSubject = "TARGET_NOT_CREDENTIAL_SUBJECT"

// ErrNotCredentialSubject is a subject_target dispatch refused: the
// credential is not a Google service account, names no subject, or names
// another one than the target.
var ErrNotCredentialSubject = errors.New("dispatch: the target is not the credential's subject")

// checkSubjectTarget enforces a definition's subject_target (G0 M31 D956a):
// its path names the mailbox or calendar as me or primary, which Google
// resolves to the service account's impersonated subject, so the action's
// target (the email policy saw) must be that subject. The credential must be
// a google_service_account with a subject equal to target.id, compared
// case-insensitively in ASCII. Any other case refuses the dispatch. The
// opened key is cleared at once.
func (e *Engine) checkSubjectTarget(ctx context.Context, conn *control.Connection, def *defs.Definition, target actionir.Target) error {
	if def == nil || def.Dispatch == nil || def.Dispatch.HTTP == nil || !def.Dispatch.HTTP.SubjectTarget {
		return nil
	}
	if conn.Credential.GetKind() != credentials.KindGoogleServiceAccount {
		return ErrNotCredentialSubject
	}
	plain, err := e.openCredential(ctx, conn)
	if err != nil {
		return err
	}
	sa, err := credentials.DecodeGoogleServiceAccount(plain)
	clear(plain)
	defer sa.Clear()
	if err != nil {
		return err
	}
	if sa.Subject == "" || !asciiEqualFold(sa.Subject, target.ID) {
		return ErrNotCredentialSubject
	}
	return nil
}

// asciiEqualFold reports whether a and b are equal with ASCII letters
// compared case-insensitively; every other byte must match exactly.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
