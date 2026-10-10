// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workloadrpc

import (
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// WaitPath is the SSE route of wait handles (G0 M5 part 2, HR-174):
// GET /v1/wait/{transaction}.
const WaitPath = "/v1/wait/"

// WithWaits adds the wait handles behind WaitStream and Wait.
func (s *Workload) WithWaits(w *approvals.Waits) *Workload {
	s.waits = w
	return s
}

// waitEvent is one SSE state event: states, codes and times only (HR-174).
type waitEvent struct {
	Handle            string         `json:"handle"`
	State             string         `json:"state"`
	Code              string         `json:"code,omitzero"`
	Deadline          time.Time      `json:"deadline,omitzero"`
	ConsumeBy         *time.Time     `json:"consume_by,omitzero"`
	EvidenceDeadline  *time.Time     `json:"evidence_deadline,omitzero"`
	ApprovalRequestID string         `json:"approval_request_id,omitzero"`
	ProposedParams    jsontext.Value `json:"proposed_params,omitzero"`
	RetryAfterSeconds int            `json:"retry_after_seconds"`
}

// WaitStream serves GET /v1/wait/{transaction} (HR-174): a workload whose
// PAP/1 credentials (method GET, the SHA-256 of the empty body) name the
// instance its transaction's run is bound to gets text/event-stream
// "state" events at once and on every change, a heartbeat every 15
// seconds, until the state is final or 5 minutes pass. Anyone else gets
// 404; beyond the wait limits, 429 with a retry time.
func (s *Workload) WaitStream(w http.ResponseWriter, r *http.Request) {
	txn, err := ids.ParseUUID(r.PathValue("transaction"))
	if s.waits == nil || err != nil || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "PAP ")
	org := tokenOrg(token)
	verifier, err := s.svc.TokenVerifier()
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	c, err := pap.VerifyRequest(verifier, s.svc.Issuer(), pap.Request{
		Method: http.MethodGet, URL: s.publicURL + WaitPath + txn.String(), BodySHA256: sha256.Sum256(nil), Token: token,
	}, r.Header.Get("PAP-Proof"), s.clk.Now())
	tok, ok := c.Token()
	if err == nil && !ok {
		err = pap.Err(pap.CodeInvalidToken)
	}
	if err == nil {
		org = tok.Instance.Org
		err = s.svc.Consume(r.Context(), org, c)
	}
	if err != nil {
		s.papHTTPError(w, r, org, err)
		return
	}
	// The stream outlives the server's write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(approvals.StreamLifetime + time.Minute))
	flusher, _ := w.(http.Flusher)
	started := false
	err = s.waits.Stream(r.Context(), org, tok.Instance.Instance, txn, func(v approvals.WaitView, heartbeat bool) error {
		if !started {
			h := w.Header()
			h.Set("Content-Type", "text/event-stream")
			h.Set("Cache-Control", "no-store")
			h.Set("X-Accel-Buffering", "no")
			w.WriteHeader(http.StatusOK)
			started = true
		}
		if heartbeat {
			_, err := fmt.Fprint(w, ": heartbeat\n\n")
			return flush(flusher, err)
		}
		b, err := json.Marshal(waitEventOf(v))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "event: state\ndata: %s\n\n", b)
		return flush(flusher, err)
	})
	if started || err == nil {
		return
	}
	switch {
	case errors.Is(err, approvals.ErrNoWait):
		http.NotFound(w, r)
	case errors.Is(err, approvals.ErrTooManyWaits):
		w.Header().Set("Retry-After", strconv.Itoa(int(approvals.RetryAfter/time.Second)))
		http.Error(w, "too many waits", http.StatusTooManyRequests)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}

func flush(f http.Flusher, err error) error {
	if err == nil && f != nil {
		f.Flush()
	}
	return err
}

func waitEventOf(v approvals.WaitView) waitEvent {
	e := waitEvent{
		Handle: v.Handle.String(), State: v.State, Code: v.Code, Deadline: v.Deadline.UTC(), ConsumeBy: v.ConsumeBy,
		EvidenceDeadline: v.EvidenceDeadline, ProposedParams: v.ProposedParams, RetryAfterSeconds: int(v.RetryAfter / time.Second),
	}
	if !v.RequestID.IsZero() {
		e.ApprovalRequestID = v.RequestID.String()
	}
	return e
}

// papHTTPError answers a PAP failure on a plain HTTP route: 401 with its
// PAP-Error code and, when the org is known, a fresh nonce.
func (s *Workload) papHTTPError(w http.ResponseWriter, r *http.Request, org ids.OrgID, err error) {
	var pe *pap.Error
	if !errors.As(err, &pe) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("PAP-Error", string(pe.Code))
	if !org.IsZero() {
		if n, err := s.svc.Nonce(r.Context(), org); err == nil {
			w.Header().Set("PAP-Nonce", n)
		}
	}
	http.Error(w, "PAP/1: "+string(pe.Code), http.StatusUnauthorized)
}
