// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package exports

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/sigv4"
)

func newS3Transport(t *testing.T, sim *s3Sim) *s3Transport {
	t.Helper()
	srv := httptest.NewServer(sim)
	t.Cleanup(srv.Close)
	base, err := url.Parse(srv.URL + "/bkt")
	if err != nil {
		t.Fatal(err)
	}
	return &s3Transport{
		client: srv.Client(), base: base, signer: sigv4.Signer{Region: "eu-west-1", Service: "s3", S3: true},
		creds: sigv4.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret/value+1"}, now: time.Now,
	}
}

func noBegin(context.Context, string) error { return nil }

// TestUploadSmallObjectIsOnePut: an object below the part size never starts
// an upload, so nothing can be left behind.
// Covers: F517
func TestUploadSmallObjectIsOnePut(t *testing.T) {
	sim := newS3Sim()
	tr := newS3Transport(t, sim)
	u := newUpload(tr, "k/small", 1024, noBegin)
	ctx := context.Background()
	if err := u.write(ctx, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := u.finish(ctx); err != nil {
		t.Fatal(err)
	}
	if b, ok := sim.object("bkt/k/small"); !ok || string(b) != "hello" {
		t.Fatalf("object %q %v", b, ok)
	}
	if u.id != "" {
		t.Fatal("a small object started an upload")
	}
}

// TestUploadCutsPartsFromTheStream: writes of any size become parts of the
// part size, however the artifact's own pieces are cut, and the object's
// hash covers the stream.
// Covers: F517
func TestUploadCutsPartsFromTheStream(t *testing.T) {
	sim := newS3Sim()
	tr := newS3Transport(t, sim)
	var begun string
	u := newUpload(tr, "k/big", 10, func(_ context.Context, id string) error {
		begun = id
		return nil
	})
	ctx := context.Background()
	var want bytes.Buffer
	for _, n := range []int{3, 4, 25, 1, 7} {
		b := bytes.Repeat([]byte{byte('a' + n)}, n)
		want.Write(b)
		if err := u.write(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	res, err := u.finish(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if begun == "" || len(u.parts) != 4 || res.ETag != `"whole-etag"` {
		t.Fatalf("begun %q, %d parts, %+v", begun, len(u.parts), res)
	}
	if b, _ := sim.object("bkt/k/big"); !bytes.Equal(b, want.Bytes()) {
		t.Fatalf("object %q, want %q", b, want.Bytes())
	}
	sum := sha256.Sum256(want.Bytes())
	if got := u.sum.Sum(nil); !bytes.Equal(got, sum[:]) {
		t.Fatalf("hash %x", got)
	}
}

func TestUploadRefusesWhatTheDestinationGotWrong(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		set  func(*s3Sim)
		code string
	}{
		"a 200 whose body is an error": {func(s *s3Sim) { s.completeError = true }, "complete_refused"},
		"a wrong checksum echoed":      {func(s *s3Sim) { s.badEcho = true }, "checksum_mismatch"},
		"a failed part":                {func(s *s3Sim) { s.failPart = 2 }, "http_5xx"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			sim := newS3Sim()
			c.set(sim)
			u := newUpload(newS3Transport(t, sim), "k/big", 4, noBegin)
			err := u.write(ctx, []byte("abcdefghij"))
			if err == nil {
				_, err = u.finish(ctx)
			}
			if code, _ := failureOf(err); code != c.code {
				t.Fatalf("got %q (%v), want %q", code, err, c.code)
			}
			if _, ok := sim.object("bkt/k/big"); ok {
				t.Fatal("the object exists")
			}
		})
	}
}

func TestAbortOfAGoneUploadSucceeds(t *testing.T) {
	sim := newS3Sim()
	if err := newS3Transport(t, sim).Abort(context.Background(), "k", "no-such-upload"); err != nil {
		t.Fatal(err)
	}
}

// TestS3KeysAreSignedAsSent: a key is signed and sent with the same path,
// its segments kept, and a dot segment never reaches a request.
func TestS3KeysAreSignedAsSent(t *testing.T) {
	sim := newS3Sim()
	tr := newS3Transport(t, sim)
	ctx := context.Background()
	if _, err := tr.Put(ctx, "a/b c/d$e", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, ok := sim.object("bkt/a/b c/d$e"); !ok {
		t.Fatalf("keys %v", sim.keys())
	}
	if _, err := tr.Put(ctx, "a/../b", []byte("x")); !errors.Is(err, sigv4.ErrDotSegment) {
		t.Fatalf("dot segment: %v", err)
	}
}

// putSim is an HTTPS PUT target.
type putSim struct {
	mu      sync.Mutex
	objects map[string][]byte
	deleted []string
	auth    []string
	// failAfter answers 500 from this many requests on; 0 never.
	failAfter int
	requests  int
}

func (s *putSim) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	s.auth = append(s.auth, r.Header.Get("Authorization"))
	body, _ := io.ReadAll(r.Body)
	key := strings.TrimPrefix(r.URL.Path, "/")
	switch r.Method {
	case http.MethodPut:
		if s.failAfter != 0 && s.requests >= s.failAfter {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		sum := sha256.Sum256(body)
		if r.Header.Get(ContentSHA256Header) != hex.EncodeToString(sum[:]) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.objects[key] = body
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		if _, ok := s.objects[key]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(s.objects, key)
		s.deleted = append(s.deleted, key)
		w.WriteHeader(http.StatusNoContent)
	}
}

func newPutTransport(t *testing.T, sim *putSim) *putTransport {
	t.Helper()
	srv := httptest.NewServer(sim)
	t.Cleanup(srv.Close)
	base, err := url.Parse(srv.URL + "/in")
	if err != nil {
		t.Fatal(err)
	}
	return &putTransport{client: srv.Client(), base: base, token: "token-1234"}
}

// TestChunkedPutsWriteTheIndexLast: a large object is chunk objects and an
// index at the object's key; the bearer token goes with every request.
// Covers: F517
func TestChunkedPutsWriteTheIndexLast(t *testing.T) {
	sim := &putSim{objects: map[string][]byte{}}
	tr := newPutTransport(t, sim)
	ctx := context.Background()
	u := newUpload(tr, "k/big", 4, noBegin)
	if err := u.write(ctx, []byte("abcdefghij")); err != nil {
		t.Fatal(err)
	}
	if _, ok := sim.objects["in/k/big"]; ok {
		t.Fatal("the index came before the last chunk")
	}
	if _, err := u.finish(ctx); err != nil {
		t.Fatal(err)
	}
	if string(sim.objects["in/k/big.chunk-000002"]) != "efgh" || !bytes.Contains(sim.objects["in/k/big"], []byte("pantherclaw.chunks/v1")) {
		t.Fatalf("objects %v", sim.objects)
	}
	for _, a := range sim.auth {
		if a != "Bearer token-1234" {
			t.Fatalf("authorization %q", a)
		}
	}
}

// TestChunkedPutAbortDeletesTheChunks: a failed chunked PUT removes what it
// wrote and leaves no index (HR-516).
// Covers: F517
func TestChunkedPutAbortDeletesTheChunks(t *testing.T) {
	sim := &putSim{objects: map[string][]byte{}, failAfter: 3}
	tr := newPutTransport(t, sim)
	ctx := context.Background()
	u := newUpload(tr, "k/big", 4, noBegin)
	if err := u.write(ctx, []byte("abcdefghijklmnop")); err == nil {
		t.Fatal("no failure")
	}
	if err := tr.Abort(ctx, u.key, u.id); err != nil {
		t.Fatal(err)
	}
	if len(sim.objects) != 0 || len(sim.deleted) != 2 {
		t.Fatalf("left %v, deleted %v", sim.objects, sim.deleted)
	}
}

func TestStatusNeverClaimsTheRemoteCopyIsGone(t *testing.T) {
	now := time.Now()
	if got, want := statusOf(ReceiptDelivered, "vault", &now), "removed here; a copy exists at vault"; got != want {
		t.Fatalf("got %q", got)
	}
	for _, v := range []string{NoticeStatement, statusOf(ReceiptDelivered, "vault", &now)} {
		for _, claim := range []string{"deleted from", "removed from the destination", "remote copy was"} {
			if strings.Contains(v, claim) {
				t.Fatalf("%q claims %q", v, claim)
			}
		}
	}
}

func TestClassAllowed(t *testing.T) {
	packs := []string{ClassEvidencePacks}
	if !classAllowed(packs, ClassEvidencePacks, false) {
		t.Fatal("refused a pack")
	}
	if classAllowed(packs, ClassEvidencePacks, true) {
		t.Fatal("a pack with captures passed without payload_captures")
	}
	if !classAllowed(append(packs, ClassPayloadCaptures), ClassEvidencePacks, true) {
		t.Fatal("refused a pack with captures")
	}
	if classAllowed(packs, ClassOrgExports, false) {
		t.Fatal("an org export passed")
	}
}
