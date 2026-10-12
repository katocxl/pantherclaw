// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// PAP/1 request headers (PAP-1 §4, §5). The run and action ids are what the
// workload says; the Authority checks the run against the verified
// instance (HR-022).
const (
	HeaderProof    = "PAP-Proof"
	HeaderNonce    = "PAP-Nonce"
	HeaderError    = "PAP-Error"
	HeaderRunID    = "PAP-Run-Id"
	HeaderActionID = "PC-Action-Id"
	// HeaderAction carries the action token to a target-enforced
	// connection (PAP-1 §10, HR-188).
	HeaderAction = "PAP-Action"
)

// nonceCacheFor bounds how long the gateway serves a nonce from its cache.
// A nonce stays valid at least 5 minutes after it is issued (HR-091), so a
// workload handed a cached one still has time to use it.
const nonceCacheFor = time.Minute

// nonces caches the org's current nonce from Authority responses (G0 M3
// constraint 7), never past its expiry.
type nonces struct {
	mu    sync.Mutex
	cur   string
	until time.Time
}

// set caches v until the earlier of exp (zero when unknown) and
// nonceCacheFor from now.
func (n *nonces) set(v string, exp time.Time) {
	if v == "" {
		return
	}
	until := time.Now().Add(nonceCacheFor)
	if !exp.IsZero() && exp.Before(until) {
		until = exp
	}
	n.mu.Lock()
	n.cur, n.until = v, until
	n.mu.Unlock()
}

// get returns the cached nonce, or "" once it is due for renewal.
func (n *nonces) get() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !time.Now().Before(n.until) {
		return ""
	}
	return n.cur
}

// Nonce returns the cached nonce, asking the Authority when there is none.
func (e *Engine) Nonce(ctx context.Context) string {
	if v := e.nonces.get(); v != "" {
		return v
	}
	if res, err := e.authority.GetNonce(ctx, &pb.GetNonceRequest{}); err == nil {
		var exp time.Time
		if t := res.GetExpireTime(); t != nil && t.IsValid() {
			exp = t.AsTime()
		}
		e.nonces.set(res.GetNonce(), exp)
	}
	return e.nonces.get()
}

// Inbound is what a request says about its workload: the PAP/1
// credentials, forwarded for the Authority to verify (HR-021), and the
// instance, environment, run and action it names, which go into the
// ActionIR and which the Authority checks against what it verified.
type Inbound struct {
	Creds *pb.WorkloadCredentials
	// HasToken: the request carries a workload token (otherwise it is
	// key-only, HR-148).
	HasToken bool
	// Instance and Env come from the token, UNVERIFIED; ok is false when
	// the token does not name them. JKT is the token's cnf.jkt, the
	// thumbprint of the key the proof must be signed with, also UNVERIFIED.
	Instance, Env, JKT string
	SubjectOK          bool
	// Run and Action are the PAP-Run-Id and PC-Action-Id headers; empty
	// when absent or not UUIDs.
	Run, Action string
}

// ReadInbound reads the PAP/1 credentials of r, whose raw body is body
// (hashed before anything parses it, HR-091), addressed to htu (the
// gateway's public URL and the path, never the Host header; PAP-1 §4).
func ReadInbound(r *http.Request, body []byte, htu string) Inbound {
	sum := sha256.Sum256(body)
	token, hasToken := strings.CutPrefix(r.Header.Get("Authorization"), "PAP ")
	in := Inbound{
		Creds: &pb.WorkloadCredentials{
			WorkloadToken: token, Proof: r.Header.Get(HeaderProof), BodySha256: sum[:], Htm: r.Method, Htu: htu,
			ClientAddress: clientAddress(r),
		},
		HasToken: hasToken,
	}
	if hasToken {
		in.Instance, in.Env, in.JKT, in.SubjectOK = tokenSubject(token)
	}
	// The nil UUID names no run and no action: every face refuses a call
	// without a run, and an action without an id gets a new one.
	if run, err := ids.ParseUUID(r.Header.Get(HeaderRunID)); err == nil && !run.IsZero() {
		in.Run = run.String()
	}
	if act, err := ids.ParseUUID(r.Header.Get(HeaderActionID)); err == nil && !act.IsZero() {
		in.Action = act.String()
	}
	return in
}

// tokenSubject reads, WITHOUT verifying, the instance, environment and key
// thumbprint a workload token names, to put them in the ActionIR and to
// match an MCP session. The Authority verifies the token, that the proof is
// signed with that key, and refuses an action whose instance or environment
// differs (IDENTITY_MISMATCH).
func tokenSubject(token string) (instance, env, jkt string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 8192 {
		return "", "", "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", "", false
	}
	var c struct {
		Sub string `json:"sub"`
		Cnf struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
		PAP struct {
			Env string `json:"env"`
		} `json:"pap"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return "", "", "", false
	}
	id, err := pap.ParseInstance(c.Sub)
	if err != nil || c.PAP.Env == "" {
		return "", "", "", false
	}
	return id.Instance.String(), c.PAP.Env, c.Cnf.JKT, true
}

// ReportUnknown reports a key-only request to the Authority (HR-148) and
// returns the PAP-Error code and nonce to refuse it with. route is the
// route the request was addressed to, when it matched one.
func (e *Engine) ReportUnknown(ctx context.Context, creds *pb.WorkloadCredentials, userAgent, route string) (pap.Code, string) {
	if len(userAgent) > 256 {
		userAgent = userAgent[:256]
	}
	res, err := e.authority.ReportUnknownWorkload(ctx, &pb.ReportUnknownWorkloadRequest{
		Workload: creds, UserAgent: strings.ToValidUTF8(userAgent, ""), Route: route,
	})
	code := pap.CodeInstanceNotAdmitted
	if err != nil {
		// A report whose proof does not verify carries its PAP-Error code.
		var ce *connect.Error
		if errors.As(err, &ce) {
			if c, ok := strings.CutPrefix(ce.Message(), "PAP/1: "); ok {
				code = pap.Code(c)
			}
		}
	}
	nonce := res.GetNonce()
	if nonce == "" {
		nonce = e.Nonce(ctx)
	}
	return code, nonce
}

// Verified is the Authority's answer about a workload whose request decides
// nothing (VerifyWorkload).
type Verified struct {
	// OK: an admitted instance of a usable agent.
	OK bool
	// Code is the PAP-Error code when not OK.
	Code          pap.Code
	Instance, Env string
	// JKT is the thumbprint of the key that signed the request.
	JKT   string
	Nonce string
	// RunExpires is when the run named in the request expires; zero when
	// none was named.
	RunExpires time.Time
}

// Verify asks the Authority to verify a workload for a request that decides
// nothing, such as an MCP tools/list (HR-021): the gateway never verifies
// a workload itself. A non-empty run must be one the instance may use, and
// the answer says when it expires. An error means the Authority could not
// be asked.
func (e *Engine) Verify(ctx context.Context, creds *pb.WorkloadCredentials, run string) (Verified, error) {
	res, err := e.authority.VerifyWorkload(ctx, &pb.VerifyWorkloadRequest{Workload: creds, RunId: run})
	if err != nil {
		return Verified{}, err
	}
	e.nonces.set(res.GetNonce(), time.Time{})
	v := Verified{
		OK: res.GetVerified(), Code: pap.Code(res.GetErrorCode()), Instance: res.GetInstanceId(), Env: res.GetEnvironmentId(),
		JKT: res.GetJkt(), Nonce: res.GetNonce(),
	}
	if res.GetRunExpiresAt() != nil {
		v.RunExpires = res.GetRunExpiresAt().AsTime()
	}
	return v, nil
}

// clientAddress is the workload's address as the gateway saw it. It is
// UNTRUSTED and only feeds the network-change alert (HR-092).
func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

// Observe asks the Authority to verify a workload in its run and to record
// a tool call its agent SDK ran without a mapping (HR-200, HR-021): the
// tool's name and the digest of its input, never the input. An error means
// the Authority could not be asked.
func (e *Engine) Observe(ctx context.Context, creds *pb.WorkloadCredentials, run, connection, tool string, input []byte) (Verified, error) {
	sum := sha256.Sum256(input)
	res, err := e.authority.RecordToolObservation(ctx, &pb.RecordToolObservationRequest{
		Workload: creds, RunId: run, ConnectionId: connection, Tool: tool, InputSha256: sum[:],
	})
	if err != nil {
		return Verified{}, err
	}
	e.nonces.set(res.GetNonce(), time.Time{})
	return Verified{OK: res.GetVerified(), Code: pap.Code(res.GetErrorCode()), Instance: res.GetInstanceId(), Nonce: res.GetNonce()}, nil
}
