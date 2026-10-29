// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// TestSPIFFEAndGCPAttestationSources: --spiffe-token reads a JWT-SVID file,
// and --gcp asks the metadata server for an ID token with the org's
// audience and the Compute Engine claims.
// Covers: PN-002.3
func TestSPIFFEAndGCPAttestationSources(t *testing.T) {
	parse := func(args ...string) attestationFlags {
		fs := flag.NewFlagSet("x", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		f := declareAttestation(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return f
	}
	org := ids.New[ids.Org]()
	svid := filepath.Join(t.TempDir(), "svid.jwt")
	if err := os.WriteFile(svid, []byte("s.v.id\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	att, err := parse("--spiffe-token", svid).attestation(context.Background(), nil, org)
	if err != nil || att.GetKind() != pantherclawv1.AttestationKind_ATTESTATION_KIND_SPIFFE_JWT || att.GetToken() != "s.v.id" {
		t.Fatalf("spiffe attestation = %v, %v", att, err)
	}

	var got *http.Request
	md := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		_, _ = w.Write([]byte("g.c.p"))
	}))
	defer md.Close()
	a := &app{env: envOf(map[string]string{"GCE_METADATA_HOST": strings.TrimPrefix(md.URL, "http://")}), http: md.Client()}
	att, err = parse("--gcp").attestation(context.Background(), a, org)
	if err != nil || att.GetKind() != pantherclawv1.AttestationKind_ATTESTATION_KIND_GCP_WORKLOAD || att.GetToken() != "g.c.p" {
		t.Fatalf("gcp attestation = %v, %v", att, err)
	}
	if got.Header.Get("Metadata-Flavor") != "Google" || got.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/identity" ||
		got.URL.Query().Get("audience") != "pantherclaw:"+org.String() || got.URL.Query().Get("format") != "full" {
		t.Errorf("metadata request = %v %v", got.URL, got.Header)
	}
	if _, err := parse("--gcp").attestation(context.Background(), a, ids.OrgID{}); err == nil {
		t.Error("--gcp without an org attested")
	}
	if _, err := parse("--gcp", "--spiffe-token", svid).attestation(context.Background(), a, org); !errors.Is(err, errAttestationSources) {
		t.Errorf("two sources: %v", err)
	}
}
