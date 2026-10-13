// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type packServer struct {
	pantherclawv1connect.UnimplementedEvidenceServiceHandler
	created *pantherclawv1.CreateEvidencePackRequest
	content []byte
	// corrupt sends content that does not match its digest.
	corrupt bool
}

func (s *packServer) CreateEvidencePack(_ context.Context, req *pantherclawv1.CreateEvidencePackRequest) (*pantherclawv1.CreateEvidencePackResponse, error) {
	s.created = req
	return &pantherclawv1.CreateEvidencePackResponse{Pack: &pantherclawv1.EvidencePack{
		Id: "0192aaaa-bbbb-7ccc-8ddd-0000000000ff", State: pantherclawv1.EvidencePackState_EVIDENCE_PACK_STATE_BUILDING,
	}}, nil
}

func (s *packServer) DownloadEvidencePack(_ context.Context, _ *pantherclawv1.DownloadEvidencePackRequest,
	stream pantherclawv1connect.EvidenceServiceDownloadEvidencePackServerStream,
) error {
	sum := sha256.Sum256(s.content)
	half := len(s.content) / 2
	for _, part := range []struct {
		off   int
		chunk []byte
	}{{0, s.content[:half]}, {half, s.content[half:]}} {
		chunk := part.chunk
		if s.corrupt {
			chunk = bytes.ToUpper(chunk)
		}
		if err := stream.Send(&pantherclawv1.DownloadEvidencePackResponse{
			Chunk: chunk, Offset: int64(part.off), TotalSize: int64(len(s.content)), ContentSha256: sum[:],
		}); err != nil {
			return err
		}
	}
	return nil
}

// TestHR196_PackCommandsAskForTheScopeAndCheckTheDownload: `pclaw pack
// create` sends the scope and what to include; `pack download` writes the
// content only when it matches the size and SHA-256 the server stated, and
// never over an existing file.
func TestHR196_PackCommandsAskForTheScopeAndCheckTheDownload(t *testing.T) {
	srv := &packServer{content: []byte("PK\x03\x04 a pack of some bytes")}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterEvidenceServiceHandler(cs, srv)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	const runID = "0192aaaa-bbbb-7ccc-8ddd-000000000001"

	code, stdout, errs := run(t, env, "pack", "create", "--run", runID, "--from", "2026-10-01T00:00:00Z", "--to", "2026-10-02T00:00:00Z")
	if code != 0 || !strings.Contains(stdout, "EVIDENCE_PACK_STATE_BUILDING") {
		t.Fatalf("pack create = %d %s %s", code, stdout, errs)
	}
	in := srv.created.GetInclude()
	if srv.created.GetRunId() != runID || srv.created.GetWithin() == nil || !in.GetReceipts() || !in.GetVersions() || !in.GetApprovals() ||
		!in.GetContainment() || in.GetCaptures() {
		t.Fatalf("request = %v", srv.created)
	}
	if code, _, _ := run(t, env, "pack", "create", "--txn", runID, "--include", "receipts,captures"); code != 0 ||
		len(srv.created.GetTransactions().GetIds()) != 1 || !srv.created.GetInclude().GetCaptures() || srv.created.GetInclude().GetVersions() {
		t.Fatalf("pack create --txn = %d, %v", code, srv.created)
	}
	for _, args := range [][]string{
		{},
		{"--run", runID, "--agent", runID},
		{"--txn", runID, "--from", "2026-10-01T00:00:00Z", "--to", "2026-10-02T00:00:00Z"},
		{"--from", "2026-10-01T00:00:00Z"},
		{"--run", runID, "--include", "everything"},
	} {
		if code, _, _ := run(t, env, append([]string{"pack", "create"}, args...)...); code == 0 {
			t.Errorf("pack create %v was accepted", args)
		}
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "pack.zip")
	if code, stdout, errs := run(t, env, "pack", "download", "0192aaaa-bbbb-7ccc-8ddd-0000000000ff", "--out", out); code != 0 ||
		!strings.Contains(stdout, "pclaw verify") {
		t.Fatalf("pack download = %d %s %s", code, stdout, errs)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, srv.content) {
		t.Fatal("the written pack is not the server's")
	}
	if code, _, _ := run(t, env, "pack", "download", "0192aaaa-bbbb-7ccc-8ddd-0000000000ff", "--out", out); code == 0 {
		t.Fatal("an existing file was overwritten")
	}
	srv.corrupt = true
	bad := filepath.Join(dir, "bad.zip")
	if code, _, errs := run(t, env, "pack", "download", "0192aaaa-bbbb-7ccc-8ddd-0000000000ff", "--out", bad); code == 0 ||
		!strings.Contains(errs, "SHA-256") {
		t.Fatalf("a corrupted download = %d %q", code, errs)
	}
	if _, err := os.Stat(bad); err == nil {
		t.Fatal("a corrupted download was written")
	}
}
