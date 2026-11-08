// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"

	"github.com/katocxl/pantherclaw/internal/evidence/sigstoretuf"
	"github.com/katocxl/pantherclaw/internal/evidence/witness"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// federationProbe runs one M35 attack. A failed prerequisite is an error,
// not a successful observation.
func (d *rangeDriver) federationProbe(st domain.Step) (domain.Observation, error) {
	var w struct {
		Attack string `json:"attack"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	refused := func(reason string) domain.Observation {
		return domain.Observation{Outcome: domain.OutcomeRefused, Reason: reason}
	}
	switch w.Attack {
	case "forged_token":
		rec := d.fedPost(tReq(d, "/fed/a2a/pay", `{"jsonrpc":"2.0","id":"1","method":"SendMessage","params":{}}`, map[string]string{
			"Authorization": "PAP-Fed not-a-token",
		}))
		if rec.code == http.StatusUnauthorized && strings.Contains(rec.body, "PANTHERCLAW_AUTHENTICATION") {
			return refused("PANTHERCLAW_AUTHENTICATION"), nil
		}
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: fmt.Sprintf("%d %s", rec.code, rec.body)}, nil
	case "unpinned_token":
		tok, err := unpinnedFedToken()
		if err != nil {
			return domain.Observation{}, err
		}
		rec := d.fedPost(tReq(d, "/fed/a2a/pay", `{"jsonrpc":"2.0","id":"1","method":"SendMessage","params":{}}`, map[string]string{
			"Authorization": "PAP-Fed " + tok,
		}))
		if rec.code == http.StatusUnauthorized && strings.Contains(rec.body, "PANTHERCLAW_AUTHENTICATION") {
			return refused("PANTHERCLAW_AUTHENTICATION"), nil
		}
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: fmt.Sprintf("%d %s", rec.code, rec.body)}, nil
	case "replay":
		if err := d.replayJTI(); err != nil {
			return domain.Observation{}, err
		}
		return refused("FEDERATION_REPLAY"), nil
	case "other_key":
		if err := l3OtherKey(); err != nil {
			return domain.Observation{}, err
		}
		return refused("L3_OTHER_KEY"), nil
	case "http_tuf":
		_, err := (&sigstoretuf.Client{Repository: "http://tuf.example"}).Fetch(context.Background())
		if errors.Is(err, sigstoretuf.ErrNotHTTPS) {
			return refused("TUF_NOT_HTTPS"), nil
		}
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: fmt.Sprint(err)}, nil
	default:
		return domain.Observation{}, fmt.Errorf("unknown federation attack %q", w.Attack)
	}
}

type fedResponse struct {
	code int
	body string
}

func tReq(d *rangeDriver, path, body string, hdr map[string]string) *http.Request {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, d.s.gateway+path, strings.NewReader(body))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return req
}

func (d *rangeDriver) fedPost(req *http.Request) fedResponse {
	res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fedResponse{body: err.Error()}
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
	return fedResponse{code: res.StatusCode, body: string(b)}
}

func (d *rangeDriver) replayJTI() error {
	peer := ids.NewV7()
	jti := "rt231-" + ids.NewV7().String()
	return d.s.pool.InTenantTx(context.Background(), d.s.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		arg := dbq.InsertFederationReplayParams{OrgID: d.s.org, PeerOrgID: peer, Kind: "token", Jti: jti, ExpiresAt: time.Now().Add(time.Minute)}
		n, err := q.InsertFederationReplay(ctx, arg)
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("first jti inserted %d rows", n)
		}
		n, err = q.InsertFederationReplay(ctx, arg)
		if err != nil {
			return err
		}
		if n != 0 {
			return fmt.Errorf("replayed jti inserted %d rows", n)
		}
		return nil
	})
}

func l3OtherKey() error {
	org := ids.New[ids.Org]()
	bind := issuers.L3Bind{Org: org, Nonce: "n", JKT: "abcdefghijklmnopqrstuvwxyz0123456789-_ABC"}
	id := "spiffe://prod.example/ns/agents/sa/runner"
	entry := issuers.SPIFFEBinding{TrustDomain: "prod.example", SPIFFEID: id}
	good := issuers.X509SVID{TrustDomain: "prod.example", SPIFFEID: id, Payload: []byte(bind.String())}
	if _, err := issuers.MatchSPIFFEX509(entry, bind, good); err != nil {
		return fmt.Errorf("matching binding: %w", err)
	}
	other := bind
	other.JKT = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	bad := good
	bad.Payload = []byte(other.String())
	if _, err := issuers.MatchSPIFFEX509(entry, bind, bad); err == nil {
		return errors.New("another key's binding was accepted")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	v, err := witness.NewVerifier("witness", pub)
	if err != nil {
		return err
	}
	at := time.Unix(1_700_000_000, 0)
	note := "logs.example/global\n1\nroot\n"
	sig := ed25519.Sign(priv, witness.Message(at, note))
	raw := make([]byte, 8+len(sig))
	binary.BigEndian.PutUint64(raw[:8], uint64(at.Unix()))
	copy(raw[8:], sig)
	if !v.Verify([]byte(note), raw) {
		return errors.New("global checkpoint cosignature did not verify")
	}
	if v.Verify([]byte("logs.example/org/other\n1\nroot\n"), raw) {
		return errors.New("a per-org note verified under the global cosignature")
	}
	return nil
}

func unpinnedFedToken() (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	s, err := jws.NewSigner("fed-"+jws.Thumbprint(pub), priv)
	if err != nil {
		return "", err
	}
	return s.Sign("pap-fed+jwt", []byte(`{"iss":"pc:org/attacker"}`))
}
