// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package siem

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/pclaw/siemforward"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/siem/ocsf"
)

// forwardFeed is a feed of fixed events.
type forwardFeed struct{ events []ocsf.Event }

func (f *forwardFeed) After(_ context.Context, _ db.TenantTx, after int64, limit int) ([]ocsf.Event, error) {
	var out []ocsf.Event
	for _, e := range f.events {
		if e.Seq > after && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *forwardFeed) Head(context.Context, db.TenantTx) (int64, error) {
	return f.events[len(f.events)-1].Seq, nil
}

// forwardKeys is one org's webhooks key.
type forwardKeys struct {
	org  ids.OrgID
	priv ed25519.PrivateKey
}

func (k *forwardKeys) SignWebhook(_ context.Context, org ids.OrgID, content []byte) ([]byte, error) {
	if org != k.org {
		return nil, errors.New("no webhooks key for this org")
	}
	return ed25519.Sign(k.priv, content), nil
}

func (k *forwardKeys) EnsureWebhookKey(context.Context, ids.OrgID) (string, error) {
	pub := k.priv.Public().(ed25519.PublicKey)
	return keys.KIDFor(keys.PurposeWebhooks, pub), nil
}

// TestT284_ExporterBatchesReachTheForwarderAsLines: the real exporter
// reads the feed, builds a batch, signs it with the destination's secret
// and the org's Ed25519 key and posts it over TLS through its egress
// client; `pclaw siem forward`, served the way the command serves it and
// requiring both signatures, writes each OCSF event as the line the mapper
// makes. The exporter's re-send of the batch is answered 2xx and not
// written again, and a batch from a destination still on HMAC only is
// refused and its events never reach the file.
// Covers: F950
func TestT284_ExporterBatchesReachTheForwarderAsLines(t *testing.T) {
	org := ids.MustParse[ids.Org]("0192f950-0000-7000-8000-0000000000aa")
	at := time.Now().UTC().Truncate(time.Second)
	event := func(seq int64, kind string) ocsf.Event {
		e := ocsf.Event{
			Seq: seq, ID: ids.NewV7(), Org: org, Kind: kind, OccurredAt: at,
			ActorType: "agent", ActorID: "0192f950-0000-7000-8000-0000000000b1",
		}
		switch kind {
		case "reflex.alert":
			e.Outcome = "OPEN"
			e.Subjects = []reflexdomain.Subject{{Type: reflexdomain.SubjectRun, ID: "0192f950-0000-7000-8000-0000000000c1"}}
			e.Attrs = map[string]string{
				ocsf.AttrID: "0192f950-0000-7000-8000-0000000000d1", ocsf.AttrRuleID: "pc.authority.self_issue", ocsf.AttrSeverity: "HIGH",
				ocsf.AttrBasis: "OBSERVED",
			}
		case "receipt.decision":
			e.Decision, e.Reason, e.Operation = "DENY", "NO_GRANT", "github.pulls.merge"
		}
		return e
	}
	feed := &forwardFeed{events: []ocsf.Event{
		event(11, "reflex.alert"), event(12, "receipt.decision"), event(13, "audit.agent.discovered"),
	}}

	// The org's webhook JWKS, as the server publishes it.
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5e}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	doc, err := json.Marshal(map[string][]jws.JWK{"keys": {jws.PublicJWK(pub, keys.KIDFor(keys.PurposeWebhooks, pub))}})
	if err != nil {
		t.Fatal(err)
	}
	orgKeys, err := siemforward.ParseJWKS(doc)
	if err != nil || len(orgKeys) != 1 {
		t.Fatalf("jwks: %v", err)
	}

	// The forwarder, over TLS on loopback (an internal destination).
	certSrv := httptest.NewUnstartedServer(http.NotFoundHandler())
	certSrv.StartTLS()
	cert, leaf := certSrv.TLS.Certificates[0], certSrv.Certificate()
	certSrv.Close()
	out := filepath.Join(t.TempDir(), "ocsf.json")
	sink, err := siemforward.OpenFile(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	secret, err := ndomain.NewSigningSecret()
	if err != nil {
		t.Fatal(err)
	}
	fwd, err := siemforward.New(siemforward.Config{
		Secrets: [][]byte{secret}, Keys: siemforward.StaticKeys(orgKeys), Sink: sink,
		Start: time.Now().Add(-time.Minute), // timestamps are whole seconds
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	addrc, done := make(chan string, 1), make(chan error, 1)
	go func() {
		done <- siemforward.Serve(ctx, fwd, siemforward.ServeConfig{
			Listen: "127.0.0.1:0", TLS: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}},
			Ready: func(a string) { addrc <- a },
		})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	var addr string
	select {
	case addr = <-addrc:
	case err := <-done:
		t.Fatalf("serve: %v", err)
	}

	// The exporter, trusting the forwarder's certificate.
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	s, err := New(nil, nil, feed, Config{PublicURL: "https://pc.example.com", ProductVersion: "1.0.0", RootCAs: roots}, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.WithWebhookKeys(&forwardKeys{org: org, priv: priv})
	var b ocsf.Builder
	to, skipped, err := s.fill(t.Context(), db.TenantTx{}, &b, 10, 0, ocsf.DataClasses)
	if err != nil || len(skipped) != 0 || to != 13 || b.Len() != 3 {
		t.Fatalf("fill: to %d, %d events, skipped %v, %v", to, b.Len(), skipped, err)
	}
	plan := &batchPlan{
		id: ids.NewV7(), from: 10, to: to, internal: true, url: "https://" + addr + "/ingest",
		secrets: [][]byte{secret}, org: org, scheme: ndomain.SchemeHMACEd25519,
	}
	if plan.body, err = b.Body(plan.id.String(), plan.from, plan.to); err != nil {
		t.Fatal(err)
	}
	if o := s.send(t.Context(), plan); !o.ok {
		t.Fatalf("send: status %d, code %q", o.status, o.code)
	}
	var want strings.Builder
	for _, e := range feed.events {
		enc, err := ocsf.Encode(ocsf.Map(e, "1.0.0"))
		if err != nil {
			t.Fatal(err)
		}
		want.Write(enc)
		want.WriteByte('\n')
	}
	read := func() string {
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		return string(got)
	}
	if got := read(); got != want.String() {
		t.Fatalf("the forwarder wrote:\n%s\nwant the mapper's lines:\n%s", got, want.String())
	}

	// The exporter retries a batch whose answer it lost: same webhook-id.
	if o := s.send(t.Context(), plan); !o.ok {
		t.Errorf("re-send: status %d, code %q", o.status, o.code)
	}
	if got := read(); got != want.String() {
		t.Errorf("the re-send was written again:\n%s", got)
	}

	// A destination still on HMAC only: the forwarder requires both.
	hmacOnly := *plan
	hmacOnly.id, hmacOnly.scheme = ids.NewV7(), ndomain.SchemeHMAC
	if hmacOnly.body, err = b.Body(hmacOnly.id.String(), plan.from, plan.to); err != nil {
		t.Fatal(err)
	}
	if o := s.send(t.Context(), &hmacOnly); o.ok || o.code != "http_401" {
		t.Errorf("HMAC only: ok %v, status %d, code %q", o.ok, o.status, o.code)
	}
	if got := read(); got != want.String() {
		t.Errorf("an HMAC-only batch was written:\n%s", got)
	}
}
