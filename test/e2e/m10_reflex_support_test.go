// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	capp "github.com/katocxl/pantherclaw/internal/cases/app"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	"github.com/katocxl/pantherclaw/internal/siem"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/signals"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// scopedPerson invites a person, binds role on a new team that holds none
// of the seeded agents, and signs them in to pclaw.
func (r *reflexStack) scopedPerson(t *testing.T, subject, email, role string) *user {
	t.Helper()
	code, out, errs := r.alice.pclaw(t, "team", "create", "--slug", "other-"+subject, "--name", "Other "+subject)
	if code != 0 {
		t.Fatalf("team create: %d %s %s", code, out, errs)
	}
	teamID := field(t, out, "id")
	code, invite, errs := r.alice.pclaw(t, "invite", "create", "--email", email)
	if code != 0 || pciToken.FindStringSubmatch(invite) == nil {
		t.Fatalf("invite %s: %d %s %s", subject, code, invite, errs)
	}
	u := r.people.user(t, subject, email)
	u.login(t, r.s.org.String(), pciToken.FindStringSubmatch(invite)[1])
	id := r.s.row(t, "SELECT id::text FROM pc.users WHERE subject = $1", subject)
	if code, o, e := r.alice.pclaw(t, "role", "bind", "--role", role, "--user", id, "--scope", "team", "--scope-id", teamID); code != 0 {
		t.Fatalf("role bind %s: %d %s %s", role, code, o, e)
	}
	u.login(t, r.s.org.String(), "")
	return u
}

// sseFrame is one event of the live stream.
type sseFrame struct{ id, event, data string }

// openStream connects to the live stream with query and header (callers
// close the body or let the context end it).
func (r *reflexStack) openStream(ctx context.Context, t *testing.T, query string, header map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.s.apiURL+"/v1/operations/stream"+query, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	res, err := (&http.Client{}).Do(req) // a stream: no client timeout; the context ends it
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// frames reads up to n events from an open stream within d.
func frames(res *http.Response, n int, d time.Duration) []sseFrame {
	out := make(chan []sseFrame, 1)
	go func() {
		var got []sseFrame
		var cur sseFrame
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if cur.event != "" {
					got = append(got, cur)
					if len(got) == n {
						out <- got
						return
					}
				}
				cur = sseFrame{}
			case strings.HasPrefix(line, "id: "):
				cur.id = strings.TrimPrefix(line, "id: ")
			case strings.HasPrefix(line, "event: "):
				cur.event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				cur.data = strings.TrimPrefix(line, "data: ")
			}
		}
		out <- got
	}()
	select {
	case got := <-out:
		_ = res.Body.Close()
		return got
	case <-time.After(d):
		_ = res.Body.Close()
		return <-out
	}
}

// stream checks the live stream (F215, HR-256): the token only in the
// Authorization header, the focus events in feed order, resume by
// Last-Event-ID.
func (r *reflexStack) stream(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := r.openStream(ctx, t, "?access_token="+r.bearer, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("a token in the query string: %d", res.StatusCode)
	}
	res = r.openStream(ctx, t, "", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d", res.StatusCode)
	}
	auth := map[string]string{"Authorization": "Bearer " + r.bearer}
	res = r.openStream(ctx, t, "?after=0", auth)
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	first := frames(res, 3, 20*time.Second)
	if len(first) < 3 {
		t.Fatalf("the stream delivered %d events: %+v", len(first), first)
	}
	if !slices.ContainsFunc(first, func(f sseFrame) bool {
		return strings.HasPrefix(f.event, "reflex.") || strings.HasPrefix(f.event, "response.")
	}) {
		t.Fatalf("no focus event: %+v", first)
	}
	// Resume after the first event: the stream continues with the second.
	auth["Last-Event-ID"] = first[0].id
	resumed := r.openStream(ctx, t, "", auth)
	defer func() { _ = resumed.Body.Close() }()
	again := frames(resumed, 1, 20*time.Second)
	if len(again) != 1 || again[0].id != first[1].id {
		t.Fatalf("resume after %s: %+v, want %s", first[0].id, again, first[1].id)
	}
}

// siemExport exports OCSF batches to an HTTPS receiver (PN-018, F537,
// HR-259, HR-260): the first delivery fails and is retried with the same
// webhook id and event ids, each with a valid Standard Webhooks signature
// under the destination's secret.
func (r *reflexStack) siemExport(t *testing.T, e ents) {
	t.Helper()
	ctx, s := context.Background(), r.s
	type delivery struct {
		id, ts, sig string
		body        []byte
	}
	var mu sync.Mutex
	var got []delivery
	recv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		mu.Lock()
		got = append(got, delivery{req.Header.Get("webhook-id"), req.Header.Get("webhook-timestamp"), req.Header.Get("webhook-signature"), b})
		n := len(got)
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(recv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(recv.Certificate())
	kp, err := keys.NewFileProvider([]string{s.kek})
	if err != nil {
		t.Fatal(err)
	}
	env := pccrypto.NewEnvelope(keystore.NewDEKStore(s.pool, kp))
	svc, err := siem.New(s.pool, env, feed.Reader{}, siem.Config{PublicURL: s.apiURL, RootCAs: roots, ProductVersion: "e2e"}, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc.WithEditions(e).WithFailures(&failures.Sink{})
	admin := s.person(t, "siem-admin", td.RoleSecurityAdmin)
	created, err := svc.Create(admin.ctx, siem.NewDestination{
		Name: "soc", URL: recv.URL + "/ingest", Internal: true, DataClasses: []string{"decisions"},
	})
	if err != nil {
		t.Fatalf("create destination: %v", err)
	}
	dest := created.Destination.ID
	if _, err := svc.Activate(admin.ctx, dest, stepup.StepUp{Credential: admin.key, At: time.Now()}); err != nil {
		t.Fatalf("activate: %v", err)
	}
	// A decision after activation: the cursor starts at the feed head.
	s.refund(t, ids.NewV7(), "2.00")
	// The first attempt fails at the receiver; wait until it has been made
	// (the decision's ledger entry is chained once its transaction ends).
	eventually(t, 30*time.Second, "the first delivery attempt", func() (bool, error) {
		if _, err := ledger.ChainAll(ctx, s.pool, s.org, 1000); err != nil {
			return false, err
		}
		st, err := svc.ExportOnce(ctx, s.org, dest)
		if err != nil || st.Delivered {
			return false, errors.Join(err, errors.New("delivered at the first attempt"))
		}
		mu.Lock()
		defer mu.Unlock()
		return len(got) == 1, nil
	})
	if _, err := svc.RetryDestination(admin.ctx, dest); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if st, err := svc.ExportOnce(ctx, s.org, dest); err != nil || !st.Delivered {
		t.Fatalf("second export: %+v %v", st, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[0].id == "" || got[0].id != got[1].id {
		t.Fatalf("deliveries %+v", got)
	}
	secret, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(created.Secret, "whsec_"))
	if err != nil {
		t.Fatal(err)
	}
	type batch struct {
		Data struct {
			Events []struct {
				Metadata struct {
					UID string `json:"uid"`
				} `json:"metadata"`
			} `json:"events"`
		} `json:"data"`
	}
	var uids [2][]string
	for i, d := range got {
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(d.id + "." + d.ts + "." + string(d.body)))
		want := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if !slices.Contains(strings.Fields(d.sig), want) {
			t.Fatalf("delivery %d: signature %q, want %q", i, d.sig, want)
		}
		var b batch
		if err := json.Unmarshal(d.body, &b); err != nil || len(b.Data.Events) == 0 {
			t.Fatalf("delivery %d: %s %v", i, d.body, err)
		}
		for _, ev := range b.Data.Events {
			uids[i] = append(uids[i], ev.Metadata.UID)
		}
	}
	if !slices.Equal(uids[0], uids[1]) {
		t.Fatalf("event ids changed on retry: %v %v", uids[0], uids[1])
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE id::text = ANY ($1)", uids[1]); n != strconv.Itoa(len(uids[1])) {
		t.Fatalf("metadata.uid is not the ledger entry id: %s of %d", n, len(uids[1]))
	}
}

// browserPerson is a person with a security key and a signed-in browser
// session, as the playbook's confirmation page sees them (session and key
// fixture rows, D58).
type browserPerson struct {
	id, key, session ids.UUID
	ctx              context.Context
}

func (r *reflexStack) browserPerson(t *testing.T, name string, n byte) browserPerson {
	t.Helper()
	s := r.s
	p := browserPerson{id: ids.NewV7(), key: ids.NewV7(), session: ids.NewV7()}
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", s.org, p.id, name)
	s.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		s.org, p.key, p.id, bytes.Repeat([]byte{n}, 16), bytes.Repeat([]byte{n}, 32))
	s.exec(t, `INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'e2e', now(), $4, now() + interval '12 hours')`, s.org, p.session, p.id, bytes.Repeat([]byte{n}, 32))
	p.ctx = tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{Org: s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: p.id}, Bindings: []td.Binding{
			{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}},
		}},
		Credential: tapp.CredBrowserSession, Session: p.session,
	})
	return p
}

// ceremony is the binding ceremony the confirmation page begins for p over
// the request's binding.
func (r *reflexStack) ceremony(t *testing.T, p browserPerson, req signals.PlaybookRequest) signals.Assertion {
	t.Helper()
	id := ids.NewV7()
	if err := r.s.pool.InTenantTx(context.Background(), r.s.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.DeleteOpenBindingCeremonies(ctx, dbq.DeleteOpenBindingCeremoniesParams{
			OrgID: r.s.org, UserID: p.id, IdentityPlaybookRequestID: &req.ID,
		}); err != nil {
			return err
		}
		return q.InsertBindingCeremony(ctx, dbq.InsertBindingCeremonyParams{
			OrgID: r.s.org, ID: id, SessionID: p.session, UserID: p.id, Challenge: req.Binding[:], AllowedCredentials: [][]byte{{1}},
			IdentityPlaybookRequestID: &req.ID, TtlSeconds: 300,
		})
	}); err != nil {
		t.Fatal(err)
	}
	return signals.Assertion{Ceremony: id, Credential: p.key}
}

// securityEvent signs a Security Event Token about the person the issuer
// knows as subject, for the transmitter's audience (iss_sub: a transmitter
// vouches only for its own users, D64).
func securityEvent(t *testing.T, key *rsa.PrivateKey, issuer, aud, subject, eventType string) string {
	t.Helper()
	now := time.Now()
	payload, err := json.Marshal(map[string]any{
		"iss": issuer, "aud": aud, "iat": now.Unix(), "jti": ids.NewV7().String(),
		"sub_id": map[string]any{"format": "iss_sub", "iss": issuer, "sub": subject},
		"events": map[string]any{eventType: map[string]any{"event_timestamp": now.Unix()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("secevent+jwt").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// sharedSignals receives SETs from a configured transmitter (PN-024, F1,
// HR-261, HR-262): the first opens a case; then two people enable the
// identity playbook and a second SET contains the person.
func (r *reflexStack) sharedSignals(t *testing.T, team, business ents) {
	t.Helper()
	s := r.s
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	idpSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) }))
	t.Cleanup(idpSrv.Close)
	container := &rapp.Containment{Pool: s.pool, Raiser: &alerts.Raiser{}, Failures: &failures.Sink{}, Editions: business}
	svc, err := signals.New(s.pool, signals.Config{PublicURL: s.apiURL}, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc.WithHTTPClient(idpSrv.Client()).WithEditions(business).WithFailures(&failures.Sink{}).WithRaiser(&alerts.Raiser{}).
		WithCases(capp.NewOpener(team)).WithContainer(container)
	mux := http.NewServeMux()
	svc.Receiver(nil).Mount(mux)

	// Carol signs in through the transmitter: it is the issuer of her identity.
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, $3, 'carol')", s.org, ids.NewV7(), idpSrv.URL)
	admin := s.person(t, "ssf-admin", td.RoleSecurityAdmin)
	tx, err := svc.Create(admin.ctx, signals.NewTransmitter{Name: "idp", Issuer: idpSrv.URL, JWKSURI: idpSrv.URL + "/jwks"})
	if err != nil {
		t.Fatalf("create transmitter: %v", err)
	}
	if _, err := svc.Activate(admin.ctx, tx.ID, stepup.StepUp{Credential: admin.key, At: time.Now()}); err != nil {
		t.Fatalf("activate transmitter: %v", err)
	}
	push := func(eventType string) int {
		tok := securityEvent(t, key, idpSrv.URL, svc.EndpointURL(s.org, tx.ID), "carol", eventType)
		req := httptest.NewRequest(http.MethodPost, "/v1/ssf/"+s.org.String()+"/"+tx.ID.String(), strings.NewReader(tok))
		req.Header.Set("Content-Type", signals.ContentType)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	opened := func() string { return s.row(t, "SELECT count(*)::text FROM pc.cases WHERE source = 'signals'") }
	if code := push(signals.TypeSessionRevoked); code != http.StatusAccepted {
		t.Fatalf("first SET: %d", code)
	}
	if n := opened(); n != "1" {
		t.Fatalf("cases opened by the first SET: %s", n)
	}
	carolID := s.row(t, "SELECT id::text FROM pc.users WHERE subject = 'carol'")
	contained := func() string {
		return s.row(t, `SELECT count(*)::text || ' ' || count(*) FILTER (WHERE control = 'DENY_ALL' AND source = 'PLAYBOOK')::text
			FROM pc.response_actions WHERE scope_type = 'principal' AND scope_id = $1`, "user:"+carolID)
	}
	if n := contained(); n != "0 0" {
		t.Fatalf("contained before the playbook: %s", n)
	}

	// Two distinct people with distinct keys enable the playbook.
	dave, erin := r.browserPerson(t, "dave", 7), r.browserPerson(t, "erin", 8)
	req, err := svc.RequestPlaybookChange(dave.ctx, signals.PlaybookEnable, []string{signals.TypeSessionRevoked, signals.TypeCredentialCompromise})
	if err != nil {
		t.Fatalf("request the playbook: %v", err)
	}
	if out, err := svc.Confirm(dave.ctx, req.ID, r.ceremony(t, dave, req)); err != nil || out.State == signals.RequestApplied {
		t.Fatalf("first confirmation: %+v %v", out, err)
	}
	if out, err := svc.Confirm(erin.ctx, req.ID, r.ceremony(t, erin, req)); err != nil || out.State != signals.RequestApplied {
		t.Fatalf("second confirmation: %+v %v", out, err)
	}
	if code := push(signals.TypeCredentialCompromise); code != http.StatusAccepted {
		t.Fatalf("second SET: %d", code)
	}
	if n := contained(); n != "1 1" {
		t.Fatalf("the person's containment actions after the second SET (all, DENY_ALL by the playbook): %s (failures: %s)", n,
			s.row(t, "SELECT coalesce(string_agg(kind || ': ' || summary, '; '), '') FROM pc.operational_failures"))
	}
	if n := opened(); n != "2" {
		t.Fatalf("cases after the second SET: %s", n)
	}
}

// live opens the live stream at the feed's head (no after, no
// Last-Event-ID) and returns the head it opened at and a function that
// waits for the first event of a kind delivered after it (F215, D71 L1).
func (r *reflexStack) live(t *testing.T) (int64, func(kind string) sseFrame) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	head, err := strconv.ParseInt(r.s.row(t, "SELECT coalesce(max(seq), 0)::text FROM pc.ledger_chain"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	res := r.openStream(ctx, t, "", map[string]string{"Authorization": "Bearer " + r.bearer})
	if res.StatusCode != http.StatusOK {
		_ = res.Body.Close()
		t.Fatalf("live stream: %d", res.StatusCode)
	}
	ch := make(chan sseFrame, 64)
	go func() {
		defer close(ch)
		defer func() { _ = res.Body.Close() }()
		var cur sseFrame
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if cur.event != "" {
					ch <- cur
				}
				cur = sseFrame{}
			case strings.HasPrefix(line, "id: "):
				cur.id = strings.TrimPrefix(line, "id: ")
			case strings.HasPrefix(line, "event: "):
				cur.event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				cur.data = strings.TrimPrefix(line, "data: ")
			}
		}
	}()
	return head, func(kind string) sseFrame {
		t.Helper()
		deadline := time.After(30 * time.Second)
		for {
			select {
			case f, ok := <-ch:
				if !ok {
					t.Fatalf("the live stream ended before a %s event", kind)
				}
				if f.event == kind {
					return f
				}
			case <-deadline:
				t.Fatalf("no live %s event within 30s", kind)
			}
		}
	}
}

func mustInt(t *testing.T, s string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		t.Fatalf("not a number: %q", s)
	}
	return n
}
