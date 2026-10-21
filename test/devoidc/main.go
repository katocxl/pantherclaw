// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command devoidc is a development-only OpenID provider for the local
// stack (G0 UI D95, the core's follow-up). The compose stack's
// mock-oauth2-server cannot send a current numeric auth_time, so a sign-in
// through it never counts as recent and what needs one (a first security
// key, HR-155) fails closed. This provider signs in any username at once,
// like the mock, and reports auth_time as the time the person submitted
// its form. It honours max_age and prompt=login by showing the form again
// when its own session is older or a fresh sign-in is asked for, as a real
// provider does, so the server's recent sign-in checks run for real.
//
// It listens only on a loopback address, because it signs anyone in. It
// has discovery, JWKS, an authorization endpoint with a sign-in form (PKCE
// S256 and a nonce required, iss on the redirect per RFC 9207), a token
// endpoint (client_secret_basic or client_secret_post; RS256 ID tokens
// from a key made at start) and userinfo. Configure it in the server as a
// provider with "dev": true and "allow_insecure_loopback": true; a
// production deployment refuses it (HR-346).
//
// It is never part of a build output: task build and the release build
// only ./cmd/..., and TestDevOIDC_IsInNoBuildOutput keeps it so.
//
//	go run ./test/devoidc --client-secret-file deploy/dev/secrets/devoidc.secret
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("devoidc", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:8282", "loopback address to listen on; the issuer is http://ADDR")
	clientID := fs.String("client-id", "pantherclaw", "the client id the server uses")
	secretFile := fs.String("client-secret-file", "", "file holding the client secret the server uses (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	bind, err := loopbackAddr(*addr)
	if err == nil && *secretFile == "" {
		err = errors.New("--client-secret-file is required")
	}
	var secret []byte
	if err == nil {
		secret, err = os.ReadFile(*secretFile) //nolint:gosec // G304: the developer's own secret file, named on the command line
		secret = []byte(strings.TrimSpace(string(secret)))
		if err == nil && len(secret) == 0 {
			err = errors.New("the client secret file is empty")
		}
	}
	var p *provider
	if err == nil {
		p, err = newProvider("http://"+*addr, *clientID, secret)
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "devoidc:", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	srv := &http.Server{Addr: bind, Handler: p.handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	_, _ = fmt.Fprintf(stderr, "devoidc: DEVELOPMENT ONLY, signs in anyone: issuer %s, client %s. In the server's auth.oidc_providers:\n"+
		`  {"name": "dev", "issuer": %q, "client_id": %q, "client_secret_file": %q, "allow_insecure_loopback": true, "dev": true}`+"\n",
		p.issuer, *clientID, p.issuer, *clientID, *secretFile)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		_, _ = fmt.Fprintln(stderr, "devoidc:", err)
		return 1
	}
	return 0
}

// loopbackAddr checks that addr is on a loopback host and returns the
// address to bind ("localhost" binds 127.0.0.1).
func loopbackAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("--addr: %w", err)
	}
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		return "", errors.New("--addr needs a port")
	}
	if host == "localhost" {
		return net.JoinHostPort("127.0.0.1", port), nil
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return "", errors.New("--addr must be a loopback address (127.0.0.1, [::1] or localhost): this provider signs anyone in")
	}
	return addr, nil
}

// loopbackURL reports whether raw is an http(s) URL on a loopback host, as
// every redirect URI must be.
func loopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return false
	}
	h := u.Hostname()
	ip := net.ParseIP(h)
	return h == "localhost" || ip != nil && ip.IsLoopback()
}

// Lifetimes.
const (
	pendingTTL = 10 * time.Minute
	codeTTL    = time.Minute
	sessionTTL = 12 * time.Hour
	tokenTTL   = 5 * time.Minute
)

// person is who signs in.
type person struct {
	Subject, Email, Name string
	Verified             bool
}

// session is the provider's own sign-in, kept in its cookie.
type session struct {
	person
	authTime time.Time
}

// authRequest is an authorization request waiting for its form.
type authRequest struct {
	redirect, state, nonce, challenge string
	at                                time.Time
}

// grant is an authorization code.
type grant struct {
	authRequest
	session
}

type provider struct {
	issuer, clientID string
	secret           []byte
	key              *rsa.PrivateKey
	kid              string

	mu       sync.Mutex
	pending  map[string]authRequest
	codes    map[string]grant
	sessions map[string]session
	// tokens are access tokens, for userinfo, with when they were issued.
	tokens map[string]grant
}

func newProvider(issuer, clientID string, secret []byte) (*provider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &provider{
		issuer: strings.TrimSuffix(issuer, "/"), clientID: clientID, secret: secret, key: key, kid: rand.Text()[:8],
		pending: map[string]authRequest{}, codes: map[string]grant{}, sessions: map[string]session{}, tokens: map[string]grant{},
	}, nil
}

func (p *provider) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /login", p.login)
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /userinfo", p.userinfo)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
}

func (p *provider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": p.issuer, "authorization_endpoint": p.issuer + "/authorize", "token_endpoint": p.issuer + "/token",
		"jwks_uri": p.issuer + "/jwks", "userinfo_endpoint": p.issuer + "/userinfo",
		"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                               []string{"openid", "email", "profile"},
		"claims_supported":                               []string{"sub", "auth_time", "nonce", "email", "email_verified", "name"},
		"prompt_values_supported":                        []string{"none", "login"},
		"authorization_response_iss_parameter_supported": true,
	})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (p *provider) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := p.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": p.kid, "use": "sig", "alg": "RS256", "n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// authorize checks the request; with a session of its own that is recent
// enough, and no prompt=login, it signs in at once, otherwise it shows the
// form (or answers login_required to prompt=none).
func (p *provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if q.Get("client_id") != p.clientID || !loopbackURL(redirect) {
		http.Error(w, "unknown client_id, or a redirect_uri that is not on a loopback host", http.StatusBadRequest)
		return
	}
	req := authRequest{redirect: redirect, state: q.Get("state"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), at: p.now()}
	prompts := strings.Fields(q.Get("prompt"))
	maxAge := -1
	if s := q.Get("max_age"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			p.back(w, r, req, url.Values{"error": {"invalid_request"}, "error_description": {"max_age is not a number of seconds"}})
			return
		}
		maxAge = n
	}
	switch {
	case q.Get("response_type") != "code" || !slices.Contains(strings.Fields(q.Get("scope")), "openid"):
		p.back(w, r, req, url.Values{"error": {"invalid_request"}, "error_description": {"response_type code and scope openid are required"}})
		return
	case q.Get("code_challenge_method") != "S256" || req.challenge == "" || req.nonce == "":
		p.back(w, r, req, url.Values{"error": {"invalid_request"}, "error_description": {"PKCE S256 and a nonce are required"}})
		return
	}
	s, ok := p.session(r)
	fresh := ok && !slices.Contains(prompts, "login") && (maxAge < 0 || !p.now().After(s.authTime.Add(time.Duration(maxAge)*time.Second)))
	switch {
	case fresh:
		p.issue(w, r, req, s)
	case slices.Contains(prompts, "none"):
		p.back(w, r, req, url.Values{"error": {"login_required"}})
	default:
		id := rand.Text()
		p.mu.Lock()
		p.expire()
		p.pending[id] = req
		p.mu.Unlock()
		p.form(w, id, ok)
	}
}

// login signs in whoever the form names: auth_time is now.
func (p *provider) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.expire()
	req, ok := p.pending[r.PostForm.Get("request")]
	delete(p.pending, r.PostForm.Get("request"))
	p.mu.Unlock()
	if !ok {
		http.Error(w, "this sign-in expired or was used; start again from the application", http.StatusBadRequest)
		return
	}
	user := strings.TrimSpace(r.PostForm.Get("username"))
	if !username.MatchString(user) {
		http.Error(w, "a username is 1 to 64 letters, digits or . _ @ -", http.StatusBadRequest)
		return
	}
	who := person{
		Subject: user, Email: strings.TrimSpace(r.PostForm.Get("email")), Name: strings.TrimSpace(r.PostForm.Get("name")),
		Verified: r.PostForm.Get("verified") != "",
	}
	if who.Email == "" {
		who.Email = user
		if !strings.Contains(user, "@") {
			who.Email = user + "@example.test"
		}
	}
	if who.Name == "" {
		who.Name = user
	}
	if len(who.Email) > 254 || len(who.Name) > 128 || !strings.Contains(who.Email, "@") {
		http.Error(w, "the email or name is not valid", http.StatusBadRequest)
		return
	}
	s := session{person: who, authTime: p.now().Truncate(time.Second)}
	id := rand.Text()
	p.mu.Lock()
	p.sessions[id] = s
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(sessionTTL / time.Second),
	})
	p.issue(w, r, req, s)
}

var username = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// sessionCookie names the provider's session cookie.
const sessionCookie = "devoidc_session"

func (p *provider) session(r *http.Request) (session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.sessions[c.Value]
	if ok && p.now().After(s.authTime.Add(sessionTTL)) {
		delete(p.sessions, c.Value)
		return session{}, false
	}
	return s, ok
}

// issue sends the client a code for s.
func (p *provider) issue(w http.ResponseWriter, r *http.Request, req authRequest, s session) {
	code := rand.Text()
	req.at = p.now()
	p.mu.Lock()
	p.codes[code] = grant{authRequest: req, session: s}
	p.mu.Unlock()
	p.back(w, r, req, url.Values{"code": {code}})
}

// back redirects to the client with v, its state and the issuer (RFC 9207).
func (p *provider) back(w http.ResponseWriter, r *http.Request, req authRequest, v url.Values) {
	v.Set("iss", p.issuer)
	if req.state != "" {
		v.Set("state", req.state)
	}
	sep := "?"
	if strings.Contains(req.redirect, "?") {
		sep = "&"
	}
	http.Redirect(w, r, req.redirect+sep+v.Encode(), http.StatusFound) //nolint:gosec // G710: only to a loopback redirect_uri (loopbackURL)
}

// expire drops what has outlived its lifetime; p.mu is held.
func (p *provider) expire() {
	now := p.now()
	for k, v := range p.pending {
		if now.After(v.at.Add(pendingTTL)) {
			delete(p.pending, k)
		}
	}
	for k, v := range p.codes {
		if now.After(v.at.Add(codeTTL)) {
			delete(p.codes, k)
		}
	}
	for k, v := range p.tokens {
		if now.After(v.at.Add(tokenTTL)) {
			delete(p.tokens, k)
		}
	}
	for k, v := range p.sessions {
		if now.After(v.authTime.Add(sessionTTL)) {
			delete(p.sessions, k)
		}
	}
}

func (p *provider) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	id, secret, basic := r.BasicAuth()
	if !basic {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != p.clientID || subtle.ConstantTimeCompare([]byte(secret), p.secret) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	p.mu.Lock()
	p.expire()
	g, ok := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || r.PostForm.Get("redirect_uri") != g.redirect || b64(sum[:]) != g.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	idToken, err := p.idToken(g)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	access := rand.Text()
	p.mu.Lock()
	p.tokens[access] = grant{authRequest: authRequest{at: p.now()}, session: g.session}
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access, "token_type": "Bearer", "expires_in": int(tokenTTL / time.Second), "id_token": idToken, "scope": "openid email profile",
	})
}

// idToken is g's ID token: RS256, auth_time the time its person submitted
// the form.
func (p *provider) idToken(g grant) (string, error) {
	now := p.now()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": p.kid})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": p.issuer, "sub": g.Subject, "aud": p.clientID, "iat": now.Unix(), "exp": now.Add(tokenTTL).Unix(),
		"auth_time": g.authTime.Unix(), "nonce": g.nonce, "email": g.Email, "email_verified": g.Verified, "name": g.Name,
		"preferred_username": g.Subject,
	})
	if err != nil {
		return "", err
	}
	input := b64(header) + "." + b64(claims)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(nil, p.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

func (p *provider) userinfo(w http.ResponseWriter, r *http.Request) {
	access, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	p.mu.Lock()
	p.expire()
	s, known := p.tokens[access]
	p.mu.Unlock()
	if !ok || !known {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sub": s.Subject, "email": s.Email, "email_verified": s.Verified, "name": s.Name, "preferred_username": s.Subject,
	})
}

var page = template.Must(template.New("form").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Development sign-in</title>
<style>body{font:16px system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem}
.dev{background:#fde68a;color:#422006;padding:.75rem;border-radius:.5rem;font-weight:600}
label{display:block;margin:1rem 0 .25rem}input[type=text]{width:100%;padding:.5rem;box-sizing:border-box}
button{margin-top:1.5rem;padding:.6rem 1.2rem}</style></head>
<body><p class="dev">DEVELOPMENT ONLY: this provider signs in any username, with no password.</p>
<h1>Sign in</h1>
{{if .Again}}<p>The application asked for a fresh sign-in.</p>{{end}}
<form method="post" action="login">
<input type="hidden" name="request" value="{{.Request}}">
<label for="username">Username</label><input type="text" id="username" name="username" required maxlength="64" autofocus>
<label for="email">Email (default: username@example.test)</label><input type="text" id="email" name="email" maxlength="254">
<label for="name">Name</label><input type="text" id="name" name="name" maxlength="128">
<label><input type="checkbox" name="verified" value="1" checked> Email verified</label>
<button type="submit">Sign in</button>
</form></body></html>
`))

// form shows the sign-in form for the waiting request id.
func (p *provider) form(w http.ResponseWriter, id string, again bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = page.Execute(w, struct {
		Request string
		Again   bool
	}{id, again})
}

// now is the provider's clock.
func (p *provider) now() time.Time { return time.Now() }
