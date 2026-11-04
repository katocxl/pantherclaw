// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package edge

import (
	"crypto/sha256"
	"encoding/binary"
	"net/http"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Resuming an approved hold through the edge (G0 M30 D945a; M29 D817a).
// Approvals bind (run, action): the edge keeps, for its session, the action
// id each request the gateway held for approval was sent with, by the
// request's fingerprint (method, the URL sent to the gateway, SHA-256 of the
// body). An identical request reuses that id, so the gateway finds the
// approved hold through its usual matching; any difference gets a fresh id.
// It applies to every connection kind through the edge.
const (
	maxHeld = 1024
	heldTTL = 24 * time.Hour
	// headerDecision is the gateway's decision header on every face.
	headerDecision   = "PC-Decision"
	decisionApproval = "REQUIRE_APPROVAL"
)

type heldKey [sha256.Size]byte

type heldEntry struct {
	action string
	at     time.Time
}

// heldActions is the session's map of held requests to their action ids.
type heldActions struct {
	mu  sync.Mutex
	m   map[heldKey]heldEntry
	now func() time.Time
}

func newHeldActions() *heldActions {
	return &heldActions{m: map[heldKey]heldEntry{}, now: time.Now}
}

// fingerprint is a request's key: method, target URL and the body's hash,
// each length-delimited.
func fingerprint(method, target string, body []byte) heldKey {
	sum := sha256.Sum256(body)
	h := sha256.New()
	for _, p := range [][]byte{[]byte(method), []byte(target), sum[:]} {
		_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(p))))
		_, _ = h.Write(p)
	}
	var k heldKey
	copy(k[:], h.Sum(nil))
	return k
}

// action returns the action id for a request: the one an identical request
// was held with in the last 24 hours, else a fresh one.
func (h *heldActions) action(k heldKey) string {
	if h == nil {
		return ids.NewV7().String()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e, ok := h.m[k]; ok {
		if h.now().Sub(e.at) < heldTTL {
			return e.action
		}
		delete(h.m, k)
	}
	return ids.NewV7().String()
}

// answered records the gateway's answer to a request sent with action: a
// hold for approval is kept (refreshing its time), anything else forgets
// the request, so a later identical request is a new action.
func (h *heldActions) answered(k heldKey, action string, hdr http.Header) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if hdr == nil || hdr.Get(headerDecision) != decisionApproval {
		delete(h.m, k)
		return
	}
	now := h.now()
	if _, ok := h.m[k]; !ok && len(h.m) >= maxHeld {
		h.evict(now)
	}
	h.m[k] = heldEntry{action: action, at: now}
}

// evict drops expired entries, then the oldest while the map is full.
func (h *heldActions) evict(now time.Time) {
	var oldest heldKey
	var first time.Time
	for k, e := range h.m {
		if now.Sub(e.at) >= heldTTL {
			delete(h.m, k)
			continue
		}
		if first.IsZero() || e.at.Before(first) {
			oldest, first = k, e.at
		}
	}
	if len(h.m) >= maxHeld {
		delete(h.m, oldest)
	}
}

// heldAnswer records the gateway's answer to a request sent with action;
// a request that got no answer changes nothing.
func (e *Edge) heldAnswer(k heldKey, action string, res *http.Response, err error) {
	if err != nil || res == nil {
		return
	}
	e.held.answered(k, action, res.Header)
}
