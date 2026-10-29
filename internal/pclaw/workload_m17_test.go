// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"io"
	"testing"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestGitLabTokenFromTheEnvironment: --gitlab-token-env sends the job's ID
// token as a GitLab attestation, and only one source may be named.
// Covers: PN-002.3
func TestGitLabTokenFromTheEnvironment(t *testing.T) {
	parse := func(args ...string) attestationFlags {
		fs := flag.NewFlagSet("x", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		f := declareAttestation(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return f
	}
	t.Setenv("PC_TEST_ID_TOKEN", " a.b.c\n")
	att, err := parse("--gitlab-token-env", "PC_TEST_ID_TOKEN").attestation(context.Background(), nil, ids.New[ids.Org]())
	if err != nil || att.GetKind() != pantherclawv1.AttestationKind_ATTESTATION_KIND_GITLAB_CI || att.GetToken() != "a.b.c" {
		t.Fatalf("attestation = %v, %v", att, err)
	}
	if _, err := parse("--gitlab-token-env", "PC_TEST_UNSET_TOKEN").attestation(context.Background(), nil, ids.OrgID{}); err == nil {
		t.Error("an empty variable attested")
	}
	if _, err := parse("--gitlab-token-env", "X", "--kubernetes-token", "f").attestation(context.Background(), nil, ids.OrgID{}); !errors.Is(err, errAttestationSources) {
		t.Errorf("two sources: %v", err)
	}
}
