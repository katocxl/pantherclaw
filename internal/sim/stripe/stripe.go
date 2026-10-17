// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package stripe is a simulated Stripe API in test mode for tests and demos
// (pantherclaw-sim stripe, G0 M14). It is shaped like Stripe where the
// pc.stripe package depends on it: form-encoded requests, integer amounts
// in minor units, lowercase currencies, a Bearer secret or restricted test
// key on every request (anything else is 401), "livemode": false on every
// object, Stripe's error envelope and Stripe's idempotency semantics (the
// same key with the same parameters replays the first answer with
// Idempotent-Replayed: true; with other parameters it is an
// idempotency_error). It serves refunds, charges, payment intents,
// transfers, connected accounts, the account's events (the read the
// stripe.account.payout_details_changed fact uses) and the balance, and it
// answers the simulator handshake (HR-221). Faults make it slow, decline,
// lose an answer after the effect, settle late, fail a refund after it was
// pending and report a recent bank-account change. Everything is
// SIMULATED; nothing here talks to Stripe or moves money.
package stripe

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json/v2"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

// Kind is the simulator's handshake kind.
const Kind = "stripe"

// Faults configures fault injection. Rates are probabilities in [0, 1].
type Faults struct {
	// Latency is added to every API request.
	Latency time.Duration
	// DeclineRate is the probability that a refund or a payment intent is
	// declined with 402 card_declined. A declined refund records nothing;
	// a declined payment intent is recorded as requires_payment_method, as
	// Stripe does.
	DeclineRate float64
	// LoseRate is the probability that a create takes effect and then
	// never answers: an unknown outcome whose effect happened.
	LoseRate float64
	// HangFor is how long a lost answer hangs before the connection is
	// dropped (default 30 s); the client's own timeout usually ends it.
	HangFor time.Duration
	// SettleAfter keeps a new refund "pending" and a confirmed payment
	// intent "processing" this long; zero settles at once.
	SettleAfter time.Duration
	// FailAfterPending makes every new refund end "failed" instead of
	// "succeeded" once it settles.
	FailAfterPending bool
	// BankChangedRecently makes every connected account report an
	// account.external_account.updated event one day ago.
	BankChangedRecently bool
}

// Require is what a request must carry.
type Require struct {
	// Keys, when set, are the only test keys accepted; otherwise any key
	// shaped like a Stripe test key (sk_test_ or rk_test_) is.
	Keys []string
	// LivemodeKey, when set, is accepted and makes every object it reads
	// or creates answer "livemode": true (for the live-mode guard tests).
	LivemodeKey string
}

// testKey is the shape of a Stripe secret or restricted test key.
var testKey = regexp.MustCompile(`^(sk|rk)_test_[A-Za-z0-9]{16,}$`)

// Server is the simulated Stripe API.
type Server struct {
	log     *slog.Logger
	require Require

	mu        sync.Mutex
	faults    Faults
	now       func() time.Time
	customers map[string]*customer
	charges   map[string]*charge
	intents   map[string]*paymentIntent
	refunds   map[string]*refund
	transfers map[string]*transfer
	accounts  map[string]*account
	order     []string // refund, payment intent and transfer ids in creation order
	idem      map[string]idemEntry
	stats     Stats
}

// New returns a simulator holding the fixtures (Fixture*).
func New(f Faults, log *slog.Logger) *Server {
	s := &Server{
		log: log, now: time.Now,
		customers: map[string]*customer{}, charges: map[string]*charge{}, intents: map[string]*paymentIntent{},
		refunds: map[string]*refund{}, transfers: map[string]*transfer{}, accounts: map[string]*account{},
		idem: map[string]idemEntry{},
	}
	s.SetFaults(f)
	s.seed()
	return s
}

// WithRequire makes the simulator require what r names, and returns it.
func (s *Server) WithRequire(r Require) *Server {
	s.require = r
	return s
}

// WithClock replaces the simulator's clock (tests), and returns it.
func (s *Server) WithClock(now func() time.Time) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
	return s
}

// SetFaults replaces the faults from the next request on, keeping every
// object recorded so far.
func (s *Server) SetFaults(f Faults) {
	if f.HangFor == 0 {
		f.HangFor = 30 * time.Second
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = f
}

func (s *Server) fault() Faults {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.faults
}

// Stats counts what the simulator has seen and done.
type Stats struct {
	// Requests counts every API request, authenticated or not (the
	// handshake and /__sim routes excepted): a guard that refuses before
	// sending leaves it unchanged.
	Requests     int `json:"requests"`
	Unauthorized int `json:"unauthorized"`
	Refunds      int `json:"refunds"`
	Intents      int `json:"payment_intents"`
	Transfers    int `json:"transfers"`
	Replays      int `json:"replays"`
	// IdempotencyErrors counts keys reused with other parameters.
	IdempotencyErrors int `json:"idempotency_errors"`
	Declines          int `json:"declines"`
	Lost              int `json:"lost"`
}

// Stats returns the current counters.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// call is one authenticated request's context.
type call struct {
	live bool
	now  time.Time
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/refunds", s.createRefund)
	mux.HandleFunc("GET /v1/refunds", s.listRefunds)
	mux.HandleFunc("GET /v1/refunds/{id}", s.getRefund)
	mux.HandleFunc("GET /v1/charges/{id}", s.getCharge)
	mux.HandleFunc("POST /v1/payment_intents", s.createIntent)
	mux.HandleFunc("GET /v1/payment_intents/{id}", s.getIntent)
	mux.HandleFunc("POST /v1/payment_intents/{id}/confirm", s.confirmIntent)
	mux.HandleFunc("POST /v1/payment_intents/{id}/cancel", s.cancelIntent)
	mux.HandleFunc("POST /v1/transfers", s.createTransfer)
	mux.HandleFunc("GET /v1/transfers/{id}", s.getTransfer)
	mux.HandleFunc("GET /v1/account", s.getPlatform)
	mux.HandleFunc("GET /v1/accounts/{id}", s.getAccount)
	mux.HandleFunc("GET /v1/events", s.listEvents)
	mux.HandleFunc("GET /v1/balance", s.getBalance)
	return handshake.Wrap(Kind, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Simulated", "true")
		w.Header().Set("Request-Id", newID("req_"))
		if r.URL.Path == "/__sim/stats" && r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, s.Stats())
			return
		}
		s.mu.Lock()
		s.stats.Requests++
		s.mu.Unlock()
		live, err := s.authenticate(r)
		if err != nil {
			s.mu.Lock()
			s.stats.Unauthorized++
			s.mu.Unlock()
			w.Header().Set("WWW-Authenticate", `Bearer realm="Stripe"`)
			err.write(w)
			return
		}
		if d := s.fault().Latency; d > 0 {
			select {
			case <-time.After(d):
			case <-r.Context().Done():
				return
			}
		}
		// Stripe-Account (acting as a connected account) is read only by
		// the events listing; anywhere else it is refused rather than
		// ignored, so a request meant for another account never acts on
		// the platform.
		if r.Header.Get("Stripe-Account") != "" && r.URL.Path != "/v1/events" {
			invalid("", "The simulator accepts Stripe-Account only on GET /v1/events.").write(w)
			return
		}
		mux.ServeHTTP(w, r.WithContext(withCall(r.Context(), live)))
	}))
}

// authenticate checks the Bearer key and returns whether it is the
// live-mode key.
func (s *Server) authenticate(r *http.Request) (bool, *apiError) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return false, &apiError{
			status: http.StatusUnauthorized, Type: "invalid_request_error",
			Message: "You did not provide an API key. Provide it in the Authorization header as a Bearer token.",
		}
	}
	key, ok := cutPrefix(h, "Bearer ")
	if ok && s.require.LivemodeKey != "" && subtle.ConstantTimeCompare([]byte(key), []byte(s.require.LivemodeKey)) == 1 {
		return true, nil
	}
	if ok && testKey.MatchString(key) && (len(s.require.Keys) == 0 || slices.ContainsFunc(s.require.Keys, func(k string) bool {
		return subtle.ConstantTimeCompare([]byte(key), []byte(k)) == 1
	})) {
		return false, nil
	}
	return false, &apiError{status: http.StatusUnauthorized, Type: "invalid_request_error", Message: "Invalid API Key provided."}
}

func cutPrefix(s, p string) (string, bool) {
	if len(s) > len(p) && s[:len(p)] == p {
		return s[len(p):], true
	}
	return "", false
}

// apiError is Stripe's error envelope.
type apiError struct {
	status  int
	Type    string `json:"type"`
	Code    string `json:"code,omitzero"`
	Decline string `json:"decline_code,omitzero"`
	Message string `json:"message"`
	Param   string `json:"param,omitzero"`
	// Intent is the payment intent a decline left behind.
	Intent any `json:"payment_intent,omitzero"`
}

func (e *apiError) write(w http.ResponseWriter) {
	writeJSON(w, e.status, map[string]any{"error": e})
}

func (e *apiError) body() []byte {
	b, _ := json.Marshal(map[string]any{"error": e}, json.Deterministic(true))
	return b
}

func invalid(param, msg string) *apiError {
	return &apiError{status: http.StatusBadRequest, Type: "invalid_request_error", Code: "parameter_invalid", Param: param, Message: msg}
}

func missing(param string) *apiError {
	return &apiError{
		status: http.StatusBadRequest, Type: "invalid_request_error", Code: "parameter_missing", Param: param,
		Message: "Missing required param: " + param + ".",
	}
}

func unknownParam(param string) *apiError {
	return &apiError{
		status: http.StatusBadRequest, Type: "invalid_request_error", Code: "parameter_unknown", Param: param,
		Message: "Received unknown parameter: " + param,
	}
}

func noSuch(kind, param, id string) *apiError {
	status := http.StatusNotFound
	if param != "" {
		status = http.StatusBadRequest
	}
	return &apiError{
		status: status, Type: "invalid_request_error", Code: "resource_missing", Param: param,
		Message: "No such " + kind + ": '" + id + "'",
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v, json.Deterministic(true))
	writeBody(w, status, b)
}

func writeBody(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// idemEntry is a saved answer to an idempotent POST.
type idemEntry struct {
	route  string
	digest [32]byte
	status int
	body   []byte
}

// idemKey is the shape of an idempotency key Stripe accepts.
var idemKey = regexp.MustCompile(`^[\x21-\x7e]{1,255}$`)

// create runs an idempotent POST: it reads the form, then, under the lock,
// replays a saved answer, refuses a key reused with other parameters, or
// runs do and saves its answer (2xx and 402 answers are saved, as Stripe
// saves the result of a request that started executing). A lost answer
// (LoseRate) hangs after the effect and drops the connection.
func (s *Server) create(w http.ResponseWriter, r *http.Request, route string, allowed []string,
	do func(c call, f *form) (int, any),
) {
	key := r.Header.Get("Idempotency-Key")
	if key != "" && !idemKey.MatchString(key) {
		invalid("", "Invalid Idempotency-Key header.").write(w)
		return
	}
	f, perr := readForm(r, allowed)
	if perr != nil {
		perr.write(w)
		return
	}
	c := callOf(r)
	s.mu.Lock()
	c.now = s.now()
	if prev, ok := s.idem[key]; key != "" && ok {
		if prev.route != route || prev.digest != f.digest {
			s.stats.IdempotencyErrors++
			s.mu.Unlock()
			(&apiError{
				status: http.StatusBadRequest, Type: "idempotency_error",
				Message: "Keys for idempotent requests can only be used with the same parameters they were first used with.",
			}).write(w)
			return
		}
		s.stats.Replays++
		s.mu.Unlock()
		w.Header().Set("Idempotent-Replayed", "true")
		writeBody(w, prev.status, prev.body)
		return
	}
	status, v := do(c, f)
	var body []byte
	if e, ok := v.(*apiError); ok {
		body = e.body()
	} else {
		body, _ = json.Marshal(v, json.Deterministic(true))
	}
	saved := status/100 == 2 || status == http.StatusPaymentRequired
	if key != "" && saved {
		s.idem[key] = idemEntry{route: route, digest: f.digest, status: status, body: body}
	}
	lose := status/100 == 2 && chance(s.faults.LoseRate)
	if lose {
		s.stats.Lost++
	}
	hangFor := s.faults.HangFor
	s.mu.Unlock()
	if lose {
		select {
		case <-time.After(hangFor):
		case <-r.Context().Done():
		}
		panic(http.ErrAbortHandler) // the effect happened; its answer never arrives
	}
	writeBody(w, status, body)
}

// chance returns true with probability p, using crypto/rand (math/rand is
// banned in this repository).
func chance(p float64) bool {
	if p <= 0 {
		return false
	}
	if p >= 1 {
		return true
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.BigEndian.Uint64(b[:])>>11)/float64(1<<53) < p
}

// newID returns prefix and 24 random characters from [A-Z2-7], the shape
// of a Stripe object id.
func newID(prefix string) string {
	return prefix + rand.Text()[:24]
}
