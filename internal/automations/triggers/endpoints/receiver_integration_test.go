// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package endpoints

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/inbound"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
)

type inboundFixture struct {
	*fixture
	st     *triggerstest.Starter
	srv    *httptest.Server
	source Source
	secret []byte
}

func newInboundFixture(t *testing.T, rate int, types ...string) *inboundFixture {
	t.Helper()
	f := &inboundFixture{fixture: newFixture(t), st: &triggerstest.Starter{}}
	trig := triggers.New(triggers.Deps{Pool: f.Pool, Starter: f.st, Editions: triggerstest.Team})
	f.svc.triggers = trig
	mux := http.NewServeMux()
	f.svc.Receiver().Mount(mux)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	c, err := f.svc.CreateEventSource(f.author(), NewSource{Name: "support", Types: types, RatePerMinute: rate})
	if err != nil {
		t.Fatal(err)
	}
	f.source, f.secret = c.Source, decodeSecret(t, c.Secret)
	return f
}

func (f *inboundFixture) url(org ids.OrgID, src ids.UUID) string {
	return f.srv.URL + "/v1/automations/events/" + org.String() + "/" + src.String()
}

// post sends body signed with secret (nil: unsigned) at ts.
func (f *inboundFixture) post(t *testing.T, url, msgID string, ts time.Time, body string, secret []byte) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if msgID != "" {
		req.Header.Set(inbound.HeaderID, msgID)
		req.Header.Set(inbound.HeaderTimestamp, strconv.FormatInt(ts.Unix(), 10))
		sig := "v1,AAAA"
		if secret != nil {
			sig = ndomain.Sign(secret, msgID, ts.Unix(), []byte(body))
		}
		req.Header.Set(inbound.HeaderSignature, sig)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (f *inboundFixture) automation(t *testing.T, name, params string) triggerstest.Automation {
	t.Helper()
	when := `"inbound":{"source":"` + f.source.ID.String() + `","type":"ticket.created"` + params + `}`
	return f.Automation(t, name, f.Definition(name, when, ""), autodomain.RolloutFull)
}

// TestHR275_InboundEventsAreSignedFreshUnseenAndDeclared: a source accepts
// nothing until a person activates it with a step-up; then only requests
// with a valid signature (current secret, or the previous one during its
// overlap), a fresh timestamp, an unseen webhook-id, a bounded JSON body
// and a declared type start work. Unknown, inactive and badly signed
// sources get one uniform 401. Bodies are never stored.
func TestHR275_InboundEventsAreSignedFreshUnseenAndDeclared(t *testing.T) {
	f := newInboundFixture(t, 0, "ticket.created", "ticket.closed")
	a := f.automation(t, "support", "")
	url := f.url(f.Org, f.source.ID)
	now := time.Now()
	body := `{"type":"ticket.created","data":{"id":"T-1"}}`

	// PENDING: uniform 401, nothing started.
	pendingStatus, pendingBody := f.post(t, url, "msg_0", now, body, f.secret)
	if pendingStatus != http.StatusUnauthorized {
		t.Fatalf("pending source: %d", pendingStatus)
	}
	// The API cannot activate (D53); a step-up can.
	if _, err := f.svc.ActivateEventSource(f.author(), f.source.ID, nil); !stepup.Is(err) {
		t.Fatalf("activation without a step-up: %v", err)
	}
	if _, err := f.svc.ActivateEventSource(f.As("user", "automation_operator"), f.source.ID, f.stepUp()); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("activation without automation.endpoints.manage: %v", err)
	}
	stale := &stepup.StepUp{Credential: f.Cred, At: time.Now().Add(-10 * time.Minute)}
	if _, err := f.svc.ActivateEventSource(f.author(), f.source.ID, stale); !stepup.Is(err) {
		t.Fatalf("stale step-up: %v", err)
	}
	src, err := f.svc.ActivateEventSource(f.author(), f.source.ID, f.stepUp())
	if err != nil || src.State != StateActive || src.ActivatedCredential == nil || *src.ActivatedCredential != f.Cred {
		t.Fatalf("activate: %+v %v", src, err)
	}

	if st, _ := f.post(t, url, "msg_1", now, body, f.secret); st != http.StatusAccepted {
		t.Fatalf("valid event: %d", st)
	}
	if f.st.Count() != 1 || f.st.Starts[0].Automation != a.ID || f.st.Starts[0].Kind != autodomain.TriggerInbound {
		t.Fatalf("starts: %+v", f.st.Starts)
	}

	other := ids.NewV7()
	for name, tc := range map[string]struct {
		url, id string
		ts      time.Time
		body    string
		secret  []byte
		want    int
	}{
		"bad signature":    {url, "msg_2", now, body, []byte("not-the-secret-not-the-secret-32"), http.StatusUnauthorized},
		"unsigned":         {url, "msg_3", now, body, nil, http.StatusUnauthorized},
		"body changed":     {url, "msg_4", now, body, f.secret, -1},
		"unknown source":   {f.url(f.Org, other), "msg_5", now, body, f.secret, http.StatusUnauthorized},
		"other org":        {f.url(ids.New[ids.Org](), f.source.ID), "msg_6", now, body, f.secret, http.StatusUnauthorized},
		"stale":            {url, "msg_7", now.Add(-6 * time.Minute), body, f.secret, http.StatusUnauthorized},
		"future":           {url, "msg_8", now.Add(6 * time.Minute), body, f.secret, http.StatusUnauthorized},
		"replayed id":      {url, "msg_1", now, `{"type":"ticket.created","data":{"id":"T-9"}}`, f.secret, http.StatusConflict},
		"undeclared type":  {url, "msg_9", now, `{"type":"ticket.deleted"}`, f.secret, http.StatusUnprocessableEntity},
		"not an object":    {url, "msg_10", now, `["ticket.created"]`, f.secret, http.StatusUnprocessableEntity},
		"duplicate member": {url, "msg_11", now, `{"type":"ticket.closed","type":"ticket.created"}`, f.secret, http.StatusUnprocessableEntity},
		"missing headers":  {url, "", now, body, nil, http.StatusBadRequest},
		"oversize":         {url, "msg_12", now, `{"type":"ticket.created","pad":"` + strings.Repeat("a", inbound.MaxBody) + `"}`, f.secret, http.StatusRequestEntityTooLarge},
	} {
		if name == "body changed" {
			// Signed over one body, sent with another.
			req, _ := http.NewRequest(http.MethodPost, tc.url, bytes.NewReader([]byte(body+" ")))
			req.Header.Set(inbound.HeaderID, tc.id)
			req.Header.Set(inbound.HeaderTimestamp, strconv.FormatInt(now.Unix(), 10))
			req.Header.Set(inbound.HeaderSignature, ndomain.Sign(f.secret, tc.id, now.Unix(), []byte(body)))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s: %d", name, resp.StatusCode)
			}
			continue
		}
		st, b := f.post(t, tc.url, tc.id, tc.ts, tc.body, tc.secret)
		if st != tc.want {
			t.Errorf("%s: %d %s, want %d", name, st, b, tc.want)
		}
		// Every 401 is the same answer: nothing says whether the source exists.
		if st == http.StatusUnauthorized && b != pendingBody {
			t.Errorf("%s: 401 body %q differs from %q", name, b, pendingBody)
		}
	}
	if f.st.Count() != 1 {
		t.Fatalf("refused requests started work: %d", f.st.Count())
	}

	// Rotation: the previous secret verifies during the overlap only.
	if _, err := f.svc.RotateEventSourceSecret(f.author(), f.source.ID, nil); !stepup.Is(err) {
		t.Fatalf("rotation without a step-up: %v", err)
	}
	fresh, err := f.svc.RotateEventSourceSecret(f.author(), f.source.ID, f.stepUp())
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := f.post(t, url, "msg_20", now, `{"type":"ticket.created","n":1}`, f.secret); st != http.StatusAccepted {
		t.Fatalf("previous secret during the overlap: %d", st)
	}
	if st, _ := f.post(t, url, "msg_21", now, `{"type":"ticket.created","n":2}`, decodeSecret(t, fresh)); st != http.StatusAccepted {
		t.Fatalf("new secret: %d", st)
	}
	f.Exec(t, "UPDATE pc.automation_event_sources SET prev_until = now() - interval '1 second' WHERE org_id = $1", f.Org)
	if st, _ := f.post(t, url, "msg_22", now, `{"type":"ticket.created","n":3}`, f.secret); st != http.StatusUnauthorized {
		t.Fatalf("previous secret after the overlap: %d", st)
	}

	// Disabled: uniform 401 again.
	if _, err := f.svc.DisableEventSource(f.author(), f.source.ID); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.post(t, url, "msg_23", now, `{"type":"ticket.created","n":4}`, decodeSecret(t, fresh)); st != http.StatusUnauthorized {
		t.Fatalf("disabled source: %d", st)
	}
	if _, err := f.svc.ActivateEventSource(f.author(), f.source.ID, f.stepUp()); err == nil {
		t.Fatal("a disabled source was re-activated")
	}

	// Receipts hold the digest, never the body; the audit record names the
	// event, never its content.
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_event_receipts WHERE org_id = $1 AND octet_length(body_sha256) = 32"); n < 3 {
		t.Fatalf("receipts: %d", n)
	}
	if n := f.Count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.automation.event_received' AND convert_from(body, 'UTF8') LIKE '%T-1%'"); n != 0 {
		t.Fatal("an event body reached the ledger")
	}
	if n := f.Count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.automation.event_received'"); n != 3 {
		t.Fatalf("event_received records: %d", n)
	}
}

// TestHR276_InboundParametersAreDeclaredTypedAndBounded: values reach the
// definition only through declared pointers, typed and bounded; a value
// that does not fit refuses the trigger (REFUSED_INVALID) and starts
// nothing; undeclared fields are ignored.
func TestHR276_InboundParametersAreDeclaredTypedAndBounded(t *testing.T) {
	f := newInboundFixture(t, 0, "ticket.created")
	if _, err := f.svc.ActivateEventSource(f.author(), f.source.ID, f.stepUp()); err != nil {
		t.Fatal(err)
	}
	f.automation(t, "refunds", `,"params":{"ticket":{"from":"/data/ticket","type":"string","pattern":"T-[0-9]{1,8}"},`+
		`"amount":{"from":"/data/amount","type":"decimal","min":"0.01","max":"50.00"},`+
		`"note":{"from":"/data/note","type":"string","max_len":20,"required":false}}`)
	url := f.url(f.Org, f.source.ID)
	now := time.Now()
	ok := `{"type":"ticket.created","data":{"ticket":"T-42","amount":"12.50","agent":"evil","principal":"user:x"}}`
	if st, _ := f.post(t, url, "m1", now, ok, f.secret); st != http.StatusAccepted || f.st.Count() != 1 {
		t.Fatalf("valid: %d, starts %d", st, f.st.Count())
	}
	p := f.st.Starts[0].Params
	if len(p) != 2 || p["ticket"].String != "T-42" || p["amount"].Decimal != "12.5" || p["amount"].Type != autodomain.ParamDecimal {
		t.Fatalf("params: %+v", p)
	}
	for i, body := range []string{
		`{"type":"ticket.created","data":{"ticket":"T-42; DROP","amount":"1"}}`,
		`{"type":"ticket.created","data":{"ticket":"T-43","amount":"50.01"}}`,
		`{"type":"ticket.created","data":{"ticket":"T-44","amount":"-1"}}`,
		`{"type":"ticket.created","data":{"ticket":"T-45"}}`,
		`{"type":"ticket.created","data":{"ticket":["T-46"],"amount":"1"}}`,
		`{"type":"ticket.created","data":{"ticket":{"id":"T-47"},"amount":"1"}}`,
		`{"type":"ticket.created","data":{"ticket":"T-48","amount":"1","note":"` + strings.Repeat("n", 21) + `"}}`,
		`{"type":"ticket.created","data":{"ticket":null,"amount":"1"}}`,
	} {
		if st, _ := f.post(t, url, "bad"+strconv.Itoa(i), now, body, f.secret); st != http.StatusAccepted {
			t.Fatalf("body %d: %d (a refused trigger is still a received event)", i, st)
		}
	}
	if f.st.Count() != 1 {
		t.Fatalf("invalid parameters started work: %d", f.st.Count())
	}
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_triggers WHERE org_id = $1 AND state = 'REFUSED_INVALID' AND reason = 'PARAMS'"); n != 8 {
		t.Fatalf("REFUSED_INVALID: %d", n)
	}
}

// TestHR278_SourceRateRefusesExcessWithOneIssue: the per-source rate
// refuses excess (429) with one owned failure per source and hour, and a
// webhook-id is unique for seven days per source (T-122, T-123).
func TestHR278_SourceRateRefusesExcessWithOneIssue(t *testing.T) {
	f := newInboundFixture(t, 2, "ping")
	sink := &failureSink{}
	f.svc.WithFailures(sink)
	if _, err := f.svc.ActivateEventSource(f.author(), f.source.ID, f.stepUp()); err != nil {
		t.Fatal(err)
	}
	url := f.url(f.Org, f.source.ID)
	now := time.Now()
	for i, want := range []int{http.StatusAccepted, http.StatusAccepted, http.StatusTooManyRequests, http.StatusTooManyRequests} {
		if st, _ := f.post(t, url, "r"+strconv.Itoa(i), now, `{"type":"ping"}`, f.secret); st != want {
			t.Fatalf("request %d: %d, want %d", i, st, want)
		}
	}
	if sink.count() != 1 {
		t.Fatalf("rate-limit issues: %d, want one for the hour", sink.count())
	}
	if n := f.Count(t, "SELECT count(*) FROM pc.automation_event_receipts WHERE org_id = $1 AND expires_at > now() + interval '6 days 23 hours'"); n != 2 {
		t.Fatalf("receipts kept seven days: %d", n)
	}
	// An expired receipt may be reused.
	f.Exec(t, "UPDATE pc.automation_event_receipts SET received_at = now() - interval '8 days', expires_at = now() - interval '1 day' WHERE org_id = $1", f.Org)
	if n, err := f.svc.PruneReceipts(context.Background(), f.Org); err != nil || n != 2 {
		t.Fatalf("prune: %d %v", n, err)
	}
}

type failureSink struct {
	mu sync.Mutex
	fs map[string]bool
}

func (s *failureSink) Report(_ context.Context, _ pgx.Tx, f reflexdomain.Failure) (ids.UUID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fs == nil {
		s.fs = map[string]bool{}
	}
	s.fs[f.DedupeKey] = true // the sink groups by dedupe key
	return ids.NewV7(), nil
}

func (s *failureSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.fs)
}
