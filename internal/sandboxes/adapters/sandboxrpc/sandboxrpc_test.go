// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sandboxrpc

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandboxes/app"
)

// TestTheSessionAnswersWithTheEnrollmentTokenItself: StartSession hands
// pclaw the sandbox instance's enrollment token itself, which enrolls, not
// its redacted form for logs.
func TestTheSessionAnswersWithTheEnrollmentTokenItself(t *testing.T) {
	org := ids.New[ids.Org]()
	tok, err := credential.New(credential.EnrollmentToken, "", org)
	if err != nil {
		t.Fatal(err)
	}
	got := started(app.Started{EnrollmentToken: tok}).GetEnrollmentToken()
	back, err := credential.Parse(credential.EnrollmentToken, got)
	if err != nil || back.Org() != org || got != tok.Reveal() {
		t.Fatalf("token %q: %v", got, err)
	}
}
