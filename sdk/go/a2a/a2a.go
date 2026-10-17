// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// Package a2a is the receiving side of a PantherClaw peer agent call (G0
// M14 D33, HR-325): an agent enrolled in PantherClaw that serves A2A takes
// a message only when the gateway sent it for a requester whose grant
// allows it, and then acts in the delegated run PantherClaw created for
// it.
//
// Every message the gateway sends carries a PAP-Action token minted for
// exactly that request (its body, operation a2a.message.send, target type
// a2a.agent) with the claim pc_peer_run naming the child run. PeerRun
// verifies the token with the target verifier (signature, issuer,
// audience, lifetime, body, single use) and returns the run id, which the
// agent then sends as its PAP-Run-Id. A message without a valid token,
// one sent directly to the agent, is refused.
package a2a

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/katocxl/pantherclaw/sdk/go/pap"
	"github.com/katocxl/pantherclaw/sdk/go/verifier"
)

// The operation and target type a peer message's token names.
const (
	Operation  = "a2a.message.send"
	TargetType = "a2a.agent"
)

// ErrNoPeerRun refuses a verified token that names no peer run: the
// connection the message came through has no peer agent, so no run was
// delegated to this agent.
var ErrNoPeerRun = errors.New("a2a: the action token names no peer run")

// uuidRE is a canonical lowercase UUID.
var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// PeerRun verifies the PAP-Action token of an A2A request (its headers
// and exact body) and returns the peer run it names. The token is spent:
// a second call with the same request is refused as a replay.
func PeerRun(ctx context.Context, v *verifier.Verifier, h http.Header, body []byte) (string, error) {
	token := h.Get(pap.HeaderAction)
	if _, err := v.Verify(ctx, token, body, func(c verifier.Claims) bool {
		return c.PAP.Op == Operation && c.PAP.Target.Type == TargetType
	}); err != nil {
		return "", err
	}
	// The signature over this payload verified: read the claim the
	// verifier's Claims do not carry.
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return "", ErrNoPeerRun
	}
	var c struct {
		PeerRun string `json:"pc_peer_run"`
	}
	if json.Unmarshal(payload, &c) != nil || !uuidRE.MatchString(c.PeerRun) {
		return "", ErrNoPeerRun
	}
	return c.PeerRun, nil
}

type runKey struct{}

// RunFromContext returns the peer run of the request a handler serves.
func RunFromContext(ctx context.Context) (string, bool) {
	r, ok := ctx.Value(runKey{}).(string)
	return r, ok && r != ""
}

// Middleware refuses, before next runs, every A2A request without a valid
// peer message token, and hands next the request unchanged with its peer
// run in the context (RunFromContext). The body is read in full, at most
// maxBody bytes (verifier.DefaultMaxBody when 0). Requests other than
// SendMessage and SendStreamingMessage (task reads, cancellations) carry
// no token; serve them with a handler of their own that checks the task
// belongs to a run of this agent.
func Middleware(v *verifier.Verifier, maxBody int64, next http.Handler) http.Handler {
	if maxBody <= 0 {
		maxBody = verifier.DefaultMaxBody
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || int64(len(body)) > maxBody {
			refuse(w, http.StatusRequestEntityTooLarge, "request_too_large")
			return
		}
		run, err := PeerRun(r.Context(), v, r.Header, body)
		if err != nil {
			status, code := http.StatusForbidden, "peer_run_missing"
			var ref *verifier.RefusalError
			if errors.As(err, &ref) {
				status, code = ref.Status(), string(ref.Code)
			}
			refuse(w, status, code)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), runKey{}, run)))
	})
}

// refuse writes an RFC 9457 problem document naming the refusal code.
func refuse(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status, "code": code})
}
