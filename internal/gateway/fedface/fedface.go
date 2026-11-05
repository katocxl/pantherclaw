// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package fedface is the gateway's federation face (G0 M35 D1024): a
// trusted peer organization's agent messages one of our listed agents.
//
//   - GET /fed/a2a/{listing}/.well-known/agent-card.json serves the listing
//     agent's card, rewritten to this face (the listing's skills only) and
//     signed with our org's federation key through the server
//     (FederationService.SignListingCard). It is public: a peer checks it
//     against the digest our federation document lists (D1022).
//   - POST /fed/a2a/{listing} takes JSON-RPC 2.0 SendMessage, GetTask and
//     CancelTask (A2A v1, D1024b), and forwards the body unchanged once
//     decided; any other method is refused with
//     FEDERATION_METHOD_NOT_DECIDED (-32601).
//
// A browser never calls this face: a request with an Origin header is
// refused. A body is at most 1 MiB. Every call carries a peer's
// `PAP-Fed` token, which the server verifies and decides under our
// cross-org grants; every answer carries our minimal PC-Fed-Receipt
// (FQ35-2). The peer's message is untrusted data.
package fedface

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Limits.
const (
	// MaxBody is the largest request body read (D1024).
	MaxBody = 1 << 20
	// maxDepth bounds JSON nesting in a request (HR-100).
	maxDepth = 32
)

// prefix is the face's path prefix.
const prefix = "/fed/a2a/"

// The JSON-RPC methods the face decides: our A2A v1 names, as internal/a2a
// and the agent-facing face use (D1024b).
const (
	MethodSend   = wire.MethodSendMessage
	MethodGet    = wire.MethodGetTask
	MethodCancel = wire.MethodCancelTask
)

// The pc.federation operations each method maps to (D1024).
const (
	OpReceive = "federation.message.receive"
	OpRead    = "federation.task.read"
	OpCancel  = "federation.task.cancel"
)

// Error codes and reasons on this face.
const (
	// codeDecided is a refused or held call (D1024: -32001).
	codeDecided = -32001
	// codeAuthenticate is a credential the server did not accept.
	codeAuthenticate = -32051
	// codeUnavailable is the Authority, or the listing's agent, not
	// answering.
	codeUnavailable = -32052

	CodeMethodNotDecided = "FEDERATION_METHOD_NOT_DECIDED"
	CodeListingUnknown   = "FEDERATION_LISTING_UNKNOWN"
	CodeBadRequest       = "FEDERATION_REQUEST_INVALID"
	CodeRefused          = "PANTHERCLAW_REFUSED"
	CodeHeld             = "PANTHERCLAW_HELD"
	CodeAuthentication   = "PANTHERCLAW_AUTHENTICATION"
	CodeUnavailable      = "PANTHERCLAW_UNAVAILABLE"
)

// Headers.
const (
	// HeaderReceipt carries our minimal signed receipt on every answer.
	HeaderReceipt = "PC-Fed-Receipt"
	// AuthScheme is the Authorization scheme of a peer's federated token.
	AuthScheme = "PAP-Fed"
)

// Agent-safe texts (HR-400): they say what happened and what to do, and
// nothing of our checks, reasons or policy (FQ35-2).
const (
	textHeld    = "held for the receiving organization's approval; ask again later"
	textRefused = "the receiving organization refused this message"
)

// listingName is a listing's name (D1022).
var listingName = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

// Listing is what the face needs of one ACTIVE federation listing: its
// name, the a2a connection to our agent, and the skills it offers.
type Listing struct {
	Name       string
	Connection *control.Connection
	Skills     []string
}

// Listings finds an ACTIVE listing by name.
type Listings interface {
	Listing(name string) (Listing, bool)
}

// SignListingCard asks the server to sign a rewritten listing card with
// our org's federation key, and returns the signed card and the JWKS that
// verifies it.
type SignListingCard func(ctx context.Context, listing string, card []byte) (signed, jwks []byte, err error)

// PeerCard returns a connection's pinned card and the binding the gateway
// calls our agent over; ok false for a connection that has none.
type PeerCard func(conn *control.Connection) (card []byte, binding string, ok bool)

// Handler serves /fed/a2a/{listing}.
type Handler struct {
	listings  Listings
	peerCard  PeerCard
	sign      SignListingCard
	publicURL string
	log       *slog.Logger
	cards     cardCache
	now       func() time.Time
	// decide authenticates, decides and forwards one call (call.go).
	decide func(ctx context.Context, c *call) answer
}

// New returns the federation face. publicURL is the gateway's public base
// URL: a peer's token names it (htu), and the served card points at it.
func New(listings Listings, peerCard PeerCard, sign SignListingCard, publicURL string, log *slog.Logger) *Handler {
	if log == nil {
		log = pclog.Discard()
	}
	h := &Handler{
		listings: listings, peerCard: peerCard, sign: sign,
		publicURL: strings.TrimSuffix(publicURL, "/"), log: log, now: time.Now,
	}
	h.decide = h.unwired
	return h
}

// Path returns the listing a request path names and the path below it:
// "/fed/a2a/{listing}" and "/fed/a2a/{listing}/…".
func Path(escapedPath string) (listing, rest string, ok bool) {
	tail, found := strings.CutPrefix(escapedPath, prefix)
	if !found {
		return "", "", false
	}
	listing, rest, _ = strings.Cut(tail, "/")
	if rest != "" {
		rest = "/" + rest
	}
	return listing, rest, listing != ""
}

// URL is the face's URL for one listing: what a peer's token names as htu.
func (h *Handler) URL(listing string) string {
	return h.publicURL + prefix + listing
}

// call is one JSON-RPC call as the face read it.
type call struct {
	r       *http.Request
	listing Listing
	body    []byte
	id      jsontext.Value
	method  string
	op      string
	params  jsontext.Value
}

// answer is what the face writes back.
type answer struct {
	status  int
	result  jsontext.Value // a JSON-RPC result, when err is nil
	err     *faceError
	receipt string // our PC-Fed-Receipt; empty when there is none to give
}

// faceError is a JSON-RPC error answer.
type faceError struct {
	status  int
	rpc     int
	reason  string
	message string
}

// ServeHTTP serves one request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name, rest, _ := Path(r.URL.EscapedPath())
	if r.Header.Get("Origin") != "" {
		// Peer gateways call this face, never a browser.
		h.fail(w, nil, &faceError{status: http.StatusForbidden, rpc: wire.CodeInvalidRequest, reason: CodeRefused, message: "origin not allowed"})
		return
	}
	var (
		l     Listing
		found bool
	)
	if listingName.MatchString(name) && h.listings != nil {
		l, found = h.listings.Listing(name)
	}
	if !found || l.Connection == nil {
		h.fail(w, nil, &faceError{status: http.StatusNotFound, rpc: wire.CodeInvalidRequest, reason: CodeListingUnknown, message: "unknown listing"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		h.fail(w, nil, &faceError{status: http.StatusRequestEntityTooLarge, rpc: wire.CodeInvalidRequest, reason: CodeBadRequest, message: "request too large"})
		return
	}
	switch rest {
	case wire.CardPath:
		h.card(ctx, w, r, l)
		return
	case "":
	default:
		h.fail(w, nil, &faceError{status: http.StatusNotFound, rpc: wire.CodeMethodNotFound, reason: CodeBadRequest, message: "not found"})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.fail(w, nil, &faceError{status: http.StatusMethodNotAllowed, rpc: wire.CodeInvalidRequest, reason: CodeBadRequest, message: "the federation endpoint takes POST only"})
		return
	}
	c := &call{r: r, listing: l, body: body}
	var ferr *faceError
	c.id, c.method, c.params, ferr = parseRPC(body)
	if ferr != nil {
		h.fail(w, c, ferr)
		return
	}
	switch c.method {
	case MethodSend:
		c.op = OpReceive
	case MethodGet:
		c.op = OpRead
	case MethodCancel:
		c.op = OpCancel
	default:
		h.fail(w, c, &faceError{status: http.StatusOK, rpc: wire.CodeMethodNotFound, reason: CodeMethodNotDecided, message: "this method is not taken through federation: use SendMessage, GetTask or CancelTask"})
		return
	}
	h.write(w, c, h.decide(ctx, c))
}

// unwired answers until the face is connected to the Authority.
func (h *Handler) unwired(context.Context, *call) answer {
	return answer{err: &faceError{status: http.StatusServiceUnavailable, rpc: codeUnavailable, reason: CodeUnavailable, message: "federation is not available"}}
}

// parseRPC decodes one JSON-RPC request strictly (HR-100): one object, no
// batch, no duplicate names, bounded depth, a string or number id.
func parseRPC(body []byte) (jsontext.Value, string, jsontext.Value, *faceError) {
	bad := func(msg string) *faceError {
		return &faceError{status: http.StatusBadRequest, rpc: wire.CodeInvalidRequest, reason: CodeBadRequest, message: msg}
	}
	if t := bytes.TrimLeft(body, " \t\r\n"); len(t) > 0 && t[0] == '[' {
		return nil, "", nil, bad("batches are not accepted: send one request per POST")
	}
	if !jsontext.Value(body).IsValid() || depth(body) > maxDepth {
		return nil, "", nil, &faceError{status: http.StatusBadRequest, rpc: wire.CodeParse, reason: CodeBadRequest, message: "parse error"}
	}
	var req struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      jsontext.Value `json:"id,omitzero"`
		Method  string         `json:"method"`
		Params  jsontext.Value `json:"params,omitzero"`
	}
	if err := json.Unmarshal(body, &req, json.RejectUnknownMembers(true)); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
		return nil, "", nil, bad("not a JSON-RPC 2.0 request")
	}
	if len(req.ID) == 0 || (req.ID.Kind() != '"' && req.ID.Kind() != '0') {
		return nil, "", nil, bad("id must be a string or a number")
	}
	if len(req.Params) > 0 && req.Params.Kind() != '{' {
		return req.ID, "", nil, &faceError{status: http.StatusBadRequest, rpc: wire.CodeInvalidParams, reason: CodeBadRequest, message: "params must be an object"}
	}
	return req.ID, req.Method, req.Params, nil
}

// depth is the deepest nesting of objects and arrays in valid JSON.
func depth(b []byte) int {
	deepest, d, inString, escaped := 0, 0, false, false
	for _, c := range b {
		switch {
		case escaped:
			escaped = false
		case inString:
			switch c {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			d++
			deepest = max(deepest, d)
		case c == '}' || c == ']':
			d--
		}
	}
	return deepest
}

// fail writes an error answer with no receipt.
func (h *Handler) fail(w http.ResponseWriter, c *call, e *faceError) {
	h.write(w, c, answer{err: e})
}

// write writes one JSON-RPC answer, with our receipt when there is one.
func (h *Handler) write(w http.ResponseWriter, c *call, a answer) {
	var id jsontext.Value = jsontext.Value("null")
	if c != nil && len(c.id) > 0 {
		id = c.id
	}
	if a.receipt != "" {
		w.Header().Set(HeaderReceipt, a.receipt)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	status := a.status
	var out any
	if a.err != nil {
		if a.err.status != 0 {
			status = a.err.status
		}
		out = map[string]any{
			"jsonrpc": "2.0", "id": id,
			"error": map[string]any{
				"code": a.err.rpc, "message": a.err.message,
				"data": map[string]any{"reason": a.err.reason},
			},
		}
	} else {
		out = map[string]any{"jsonrpc": "2.0", "id": id, "result": a.result}
	}
	if status == 0 {
		status = http.StatusOK
	}
	b, err := json.Marshal(out, json.Deterministic(true))
	if err != nil {
		h.log.Error("gateway.federation_answer", pclog.Err(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
