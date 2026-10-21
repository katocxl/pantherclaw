// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webguard"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/operations/stream"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// The range's browser (G0 UI, RT-060, RT-061): bob's signed-in browser,
// the payments approver of the person capability, sends the requests a
// page could make with his session cookie: from the console's own origin
// or from another site's page, to the Connect API or the live operations
// stream.

const capBrowser = app.Capability("browser")

// needsBrowser reports a scenario that uses the browser.
func needsBrowser(sc domain.Scenario) bool { return requires(sc, string(capBrowser)) }

// setupBrowser lets bob read the operations stream (Auditor), as a
// security engineer watching it would.
func (d *rangeDriver) setupBrowser() {
	t, s := d.t, d.s
	bob := s.row(t, "SELECT id::text FROM pc.users WHERE org_id = $1 AND subject = 'bob'", s.org)
	if code, o, e := d.admin.pclaw(t, "role", "bind", "--role", "auditor", "--user", bob); code != 0 {
		t.Fatalf("bind auditor: %d %s %s", code, o, e)
	}
}

// browserWith is the browser.call arguments the driver reads.
type browserWith struct {
	Target string `json:"target"`
	Origin string `json:"origin"`
	CSRF   bool   `json:"csrf"`
	Bearer bool   `json:"bearer"`
	Method string `json:"method"`
	Body   string `json:"body"`
}

// reasonPrefix is the reason code a refusal starts its message with.
var reasonPrefix = regexp.MustCompile(`^([A-Z][A-Z0-9_]{2,63}):`)

// browserCall sends one request from bob's browser.
func (d *rangeDriver) browserCall(st domain.Step) (domain.Observation, error) {
	var w browserWith
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	if len(d.reviewers) == 0 || d.reviewers[0].b == nil {
		return domain.Observation{}, fmt.Errorf("browser.call needs the person setup")
	}
	b := d.reviewers[0].b
	base := b.s.url
	path := stream.Path
	var body []byte
	if w.Target == "api" {
		path = pantherclawv1connect.AccessServiceWhoAmIProcedure
	}
	ctype := map[string]string{
		"json": "application/json", "proto": "application/proto", "form": "application/x-www-form-urlencoded", "text": "text/plain",
	}[w.Body]
	switch w.Body {
	case "json":
		body = []byte("{}")
	case "proto":
		body, _ = proto.Marshal(&pantherclawv1.WhoAmIRequest{})
	case "form":
		body = []byte("a=1")
	case "text":
		body = []byte("{}")
	}
	u := base + path
	if w.Method == http.MethodGet && w.Target == "api" {
		// The Connect GET form of an idempotent call.
		u += "?" + url.Values{"connect": {"v1"}, "encoding": {"json"}, "message": {"{}"}}.Encode()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var rd io.Reader
	if w.Method == http.MethodPost {
		rd = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, w.Method, u, rd)
	if err != nil {
		return domain.Observation{}, err
	}
	if w.Method == http.MethodPost {
		req.Header.Set("Content-Type", ctype)
	}
	if w.CSRF {
		req.Header.Set(webguard.CSRFHeader, "1")
	}
	if w.Bearer {
		// Any bearer value: a call carrying both is refused before either
		// is checked (HR-343).
		req.Header.Set("Authorization", "Bearer pca_range_"+d.fix["nonce"])
	}
	switch w.Origin {
	case "same_origin":
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Origin", base)
	case "origin_only":
		req.Header.Set("Origin", base)
	case "cross_site":
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Origin", "https://attacker.example")
	case "same_site":
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Origin", "https://evil.localhost")
	case "typed_url":
		req.Header.Set("Sec-Fetch-Site", "none")
	case "other_origin":
		req.Header.Set("Origin", "https://attacker.example")
	case "no_proof":
	}
	res, err := b.c.Do(req)
	if err != nil {
		return domain.Observation{}, err
	}
	defer func() { _ = res.Body.Close() }()
	obs := domain.Observation{Detail: fmt.Sprintf("HTTP %d", res.StatusCode)}
	if res.StatusCode == http.StatusOK {
		obs.Outcome = domain.OutcomeAllow
		if w.Target == "ops_stream" {
			// The stream opens with a comment; reading it proves events flow.
			line, _ := bufio.NewReader(res.Body).ReadString('\n')
			obs.Detail += " " + strings.TrimSpace(line)
			if !strings.HasPrefix(line, ": stream open") {
				obs.Outcome = domain.OutcomeUnknown
			}
			return obs, nil
		}
		raw, _ := io.ReadAll(io.LimitReader(res.Body, domain.MaxResponseBytes))
		obs.Response = raw
		return obs, nil
	}
	obs.Outcome = domain.OutcomeRefused
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	msg := strings.TrimSpace(string(raw))
	var ce struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &ce) == nil && ce.Message != "" {
		msg = ce.Message
	}
	if m := reasonPrefix.FindStringSubmatch(msg); m != nil {
		obs.Code = m[1]
	}
	obs.Detail += " " + msg
	return obs, nil
}
