// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package signals

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/signals/setverify"
)

type recordingSink struct{ got []Received }

func (s *recordingSink) Received(_ context.Context, _ db.TenantTx, r Received) error {
	s.got = append(s.got, r)
	return nil
}

type rxFixture struct {
	p          *db.Pool
	org        ids.OrgID
	alice, bob ids.UUID
	cred       ids.UUID
	key, other *rsa.PrivateKey
	issuer     string
	tx         ids.UUID
	svc        *Service
	sink       *recordingSink
	mux        *http.ServeMux
	clk        *clock.Fake
}

func newRxFixture(t *testing.T) *rxFixture {
	t.Helper()
	d := dbtest.New(t)
	f := &rxFixture{p: d.AppPool(t), org: ids.New[ids.Org](), alice: ids.NewV7(), bob: ids.NewV7(), cred: ids.NewV7(),
		sink: &recordingSink{}, clk: clock.NewFake(time.Now())}
	var err error
	if f.key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	if f.other, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	set, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(set) }))
	t.Cleanup(srv.Close)
	f.issuer = srv.URL
	if f.svc, err = New(f.p, Config{PublicURL: "https://pc.example.com"}, f.clk, nil); err != nil {
		t.Fatal(err)
	}
	// The test key server is on 127.0.0.1, which the egress client refuses.
	f.svc.WithHTTPClient(srv.Client()).WithSink(f.sink)
	f.mux = http.NewServeMux()
	f.svc.Receiver().Mount(f.mux)

	f.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'ssf')", f.org)
	f.exec(t, `INSERT INTO pc.users (org_id, id, issuer, subject, email) VALUES ($1, $2, 'https://login.example.com', 'user-7', 'alice@example.com')`,
		f.org, f.alice)
	f.exec(t, `INSERT INTO pc.users (org_id, id, issuer, subject, email) VALUES ($1, $2, 'https://login.example.com', 'user-8', 'shared@example.com')`,
		f.org, f.bob)
	f.exec(t, `INSERT INTO pc.users (org_id, id, issuer, subject, email) VALUES ($1, $2, 'https://other.example.com', 'x', 'shared@example.com')`,
		f.org, ids.NewV7())
	f.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		f.org, f.cred, f.alice, bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32))
	f.tx = f.transmitter(t, "idp", true)
	return f
}

func (f *rxFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (f *rxFixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// transmitter stores a transmitter as Create (and Activate) would.
func (f *rxFixture) transmitter(t *testing.T, name string, active bool) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.InsertSSFTransmitter(ctx, dbq.InsertSSFTransmitterParams{
			OrgID: f.org, ID: id, Name: name, Issuer: f.issuer, JwksUri: f.issuer + "/jwks", Audience: f.svc.EndpointURL(f.org, id),
			CreatedBy: f.alice.String(),
		}); err != nil {
			return err
		}
		if !active {
			return nil
		}
		_, err := q.ActivateSSFTransmitter(ctx, dbq.ActivateSSFTransmitterParams{ActivatedBy: &f.alice, ActivatedCredential: &f.cred, OrgID: f.org, ID: id})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *rxFixture) token(t *testing.T, key *rsa.PrivateKey, tx ids.UUID, mut func(map[string]any)) string {
	t.Helper()
	c := map[string]any{
		"iss": f.issuer, "aud": f.svc.EndpointURL(f.org, tx), "iat": f.clk.Now().Unix(), "jti": ids.NewV7().String(),
		"sub_id": map[string]any{"format": "iss_sub", "iss": "https://login.example.com", "sub": "user-7"},
		"events": map[string]any{TypeSessionRevoked: map[string]any{"event_timestamp": f.clk.Now().Unix()}},
	}
	if mut != nil {
		mut(c)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("secevent+jwt").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type answer struct {
	status int
	Err    string `json:"err"`
}

func (f *rxFixture) post(t *testing.T, org ids.OrgID, tx ids.UUID, contentType, body string) answer {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/ssf/"+org.String()+"/"+tx.String(), strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	a := answer{status: rec.Code}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
			t.Fatalf("body %q: %v", rec.Body.String(), err)
		}
	}
	return a
}

// TestT113_ReceiverAcceptsOnlyFreshSignedEventsFromActiveTransmitters: the
// receiver records a verified SET once and hands it on, refuses a replayed
// jti, a forged signature, an unknown or pending transmitter, a wrong
// media type and an oversize body, and rate-limits a transmitter (HR-261).
func TestT113_ReceiverAcceptsOnlyFreshSignedEventsFromActiveTransmitters(t *testing.T) {
	f := newRxFixture(t)
	tok := f.token(t, f.key, f.tx, nil)
	if a := f.post(t, f.org, f.tx, ContentType, tok); a.status != http.StatusAccepted {
		t.Fatalf("first push: %+v", a)
	}
	if len(f.sink.got) != 1 || f.sink.got[0].User != f.alice || f.sink.got[0].MatchBasis != "iss_sub" || f.sink.got[0].EventType != TypeSessionRevoked {
		t.Fatalf("sink = %+v", f.sink.got)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.ssf_events WHERE outcome = 'ACCEPTED' AND user_id = $1", f.alice); n != 1 {
		t.Fatalf("accepted events = %d", n)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.signals.event_received'"); n != 1 {
		t.Fatalf("ledger entries = %d", n)
	}

	refusals := []struct {
		name        string
		org         ids.OrgID
		tx          ids.UUID
		contentType string
		body        string
		status      int
		code        string
	}{
		{"replayed jti", f.org, f.tx, ContentType, tok, http.StatusBadRequest, setverify.CodeInvalidRequest},
		{"forged signature", f.org, f.tx, ContentType, f.token(t, f.other, f.tx, nil), http.StatusBadRequest, setverify.CodeAuthFailed},
		{"audience of another transmitter", f.org, f.tx, ContentType, f.token(t, f.key, ids.NewV7(), nil), http.StatusBadRequest,
			setverify.CodeInvalidAudience},
		{"stale", f.org, f.tx, ContentType, f.token(t, f.key, f.tx, func(c map[string]any) { c["iat"] = f.clk.Now().Add(-time.Hour).Unix() }),
			http.StatusBadRequest, setverify.CodeInvalidRequest},
		{"unknown transmitter", f.org, ids.NewV7(), ContentType, tok, http.StatusNotFound, setverify.CodeInvalidRequest},
		{"pending transmitter", f.org, f.transmitter(t, "pending", false), ContentType, tok, http.StatusNotFound, setverify.CodeInvalidRequest},
		{"another org", ids.New[ids.Org](), f.tx, ContentType, tok, http.StatusNotFound, setverify.CodeInvalidRequest},
		{"wrong media type", f.org, f.tx, "application/json", tok, http.StatusBadRequest, setverify.CodeInvalidRequest},
		{"oversize body", f.org, f.tx, ContentType, strings.Repeat("a", MaxBody+1), http.StatusBadRequest, setverify.CodeInvalidRequest},
	}
	for _, r := range refusals {
		if a := f.post(t, r.org, r.tx, r.contentType, r.body); a.status != r.status || a.Err != r.code {
			t.Errorf("%s: %+v, want %d %s", r.name, a, r.status, r.code)
		}
	}
	if len(f.sink.got) != 1 {
		t.Fatalf("a refused push reached the sink: %+v", f.sink.got)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.ssf_events"); n != 1 {
		t.Fatalf("events = %d", n)
	}
	if n := f.count(t, "SELECT events_refused FROM pc.ssf_transmitters WHERE id = $1", f.tx); n != 4 {
		t.Fatalf("refusals counted = %d", n)
	}

	// Rate limit per transmitter.
	limited := false
	for range RateLimit {
		if a := f.post(t, f.org, f.tx, ContentType, "x"); a.status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("the transmitter was never rate-limited")
	}
}

// TestHR261_SubjectMatchingAndEventTypes: an event about nobody, about an
// ambiguous email or of a type PantherClaw does not act on is recorded and
// never handed on; the verification event is acknowledged.
func TestHR261_SubjectMatchingAndEventTypes(t *testing.T) {
	f := newRxFixture(t)
	cases := []struct {
		name    string
		mut     func(map[string]any)
		outcome string
		sink    bool
	}{
		{"email", func(c map[string]any) {
			c["sub_id"] = map[string]any{"format": "email", "email": "Alice@Example.com"}
			c["events"] = map[string]any{TypeAccountDisabled: map[string]any{}}
		}, OutcomeAccepted, true},
		{"ambiguous email", func(c map[string]any) { c["sub_id"] = map[string]any{"format": "email", "email": "shared@example.com"} }, OutcomeUnmatched, false},
		{"unknown person", func(c map[string]any) {
			c["sub_id"] = map[string]any{"format": "iss_sub", "iss": "https://login.example.com", "sub": "nobody"}
		}, OutcomeUnmatched, false},
		{"opaque", func(c map[string]any) { c["sub_id"] = map[string]any{"format": "opaque", "id": "x"} }, OutcomeUnmatched, false},
		{"other event type", func(c map[string]any) {
			c["events"] = map[string]any{"https://schemas.openid.net/secevent/caep/event-type/assurance-level-change": map[string]any{}}
		}, OutcomeIgnored, false},
		{"verification", func(c map[string]any) {
			delete(c, "sub_id")
			c["events"] = map[string]any{TypeVerification: map[string]any{"state": "abc"}}
		}, OutcomeVerification, false},
	}
	for _, c := range cases {
		before := len(f.sink.got)
		if a := f.post(t, f.org, f.tx, ContentType, f.token(t, f.key, f.tx, c.mut)); a.status != http.StatusAccepted {
			t.Fatalf("%s: %+v", c.name, a)
		}
		if got := len(f.sink.got) > before; got != c.sink {
			t.Errorf("%s: handed on %v, want %v", c.name, got, c.sink)
		}
		if n := f.count(t, "SELECT count(*) FROM pc.ssf_events WHERE outcome = $1", c.outcome); n == 0 {
			t.Errorf("%s: no %s event", c.name, c.outcome)
		}
	}
	if f.sink.got[0].User != f.alice || f.sink.got[0].MatchBasis != "email" {
		t.Errorf("email match = %+v", f.sink.got[0])
	}
}
