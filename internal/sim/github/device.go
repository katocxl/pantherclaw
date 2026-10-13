// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package github

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"net/http"
	"strings"
	"time"
)

// GitHub sign-in through a sign-in App's device flow (G0 M8 P2f), as GitHub
// serves it: pclaw github link asks for a device code, a person enters the
// user code at GitHub and signs in, and pclaw polls for a user access
// token. The server checks the token with the App's client secret (POST
// /applications/{client_id}/token, which names its account only if the App
// issued it) and then revokes it (DELETE). The sign-in App is not the App
// that merges: it has no permissions and is installed nowhere. In the
// simulator RegisterSignInApp sets it, and a test says who signs in with
// AuthorizeDevice.

// deviceExpiry is how long a device code lives (GitHub: 15 minutes).
const deviceExpiry = 15 * time.Minute

// deviceGrant is the device flow's grant type (RFC 8628).
const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

// DeviceUser is the GitHub account a person signs in as.
type DeviceUser struct {
	ID    int64
	Login string
}

// deviceState is the sign-in App, its device codes and the user tokens they
// became.
type deviceState struct {
	clientID, secret string
	codes            map[string]*deviceCode // by device code
	users            map[string]DeviceUser  // user access token → account
	// auto signs every later code in as this account (SignInAs).
	auto *DeviceUser
}

type deviceCode struct {
	user     string // the code the person enters
	expires  time.Time
	signedIn *DeviceUser
	denied   bool
	issued   bool
}

func (s *Server) deviceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /login/device/code", s.deviceCode)
	mux.HandleFunc("POST /login/oauth/access_token", s.deviceToken)
	mux.HandleFunc("GET /user", s.user)
	mux.HandleFunc("POST /applications/{client_id}/token", s.checkToken)
	mux.HandleFunc("DELETE /applications/{client_id}/token", s.revokeToken)
}

func random(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func deviceJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
}

// RegisterSignInApp sets the sign-in App: its client id and secret.
func (s *Server) RegisterSignInApp(clientID, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.device.clientID, s.device.secret = clientID, secret
}

// deviceCode starts a sign-in for the sign-in App's client id.
func (s *Server) deviceCode(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.device.clientID == "" || r.PostFormValue("client_id") != s.device.clientID {
		deviceJSON(w, http.StatusUnauthorized, map[string]string{"error": "incorrect_client_credentials"})
		return
	}
	if s.device.codes == nil {
		s.device.codes, s.device.users = map[string]*deviceCode{}, map[string]DeviceUser{}
	}
	code, user := random(20), strings.ToUpper(random(2)+"-"+random(2))
	c, interval := &deviceCode{user: user, expires: s.now().Add(deviceExpiry)}, 5
	if s.device.auto != nil {
		u := *s.device.auto
		c.signedIn, interval = &u, 1
	}
	s.device.codes[code] = c
	deviceJSON(w, http.StatusOK, map[string]any{
		"device_code": code, "user_code": user, "verification_uri": origin(r) + "/login/device",
		"expires_in": int(deviceExpiry.Seconds()), "interval": interval,
	})
}

// deviceToken answers a poll for a device code's user access token.
func (s *Server) deviceToken(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	answer := func(errCode string) { deviceJSON(w, http.StatusOK, map[string]string{"error": errCode}) }
	c := s.device.codes[r.PostFormValue("device_code")]
	switch {
	case s.device.clientID == "" || r.PostFormValue("client_id") != s.device.clientID:
		deviceJSON(w, http.StatusUnauthorized, map[string]string{"error": "incorrect_client_credentials"})
	case r.PostFormValue("grant_type") != deviceGrant:
		answer("unsupported_grant_type")
	case c == nil || c.issued:
		answer("bad_verification_code")
	case !s.now().Before(c.expires):
		answer("expired_token")
	case c.denied:
		answer("access_denied")
	case c.signedIn == nil:
		answer("authorization_pending")
	default:
		c.issued = true
		token := "ghu_" + random(18)
		s.device.users[token] = *c.signedIn
		deviceJSON(w, http.StatusOK, map[string]string{"access_token": token, "token_type": "bearer", "scope": ""})
	}
}

// user answers GET /user: the account a user access token belongs to.
func (s *Server) user(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	auth := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok {
		token, _ = strings.CutPrefix(auth, "token ")
	}
	u, known := s.device.users[token]
	if !known {
		deviceJSON(w, http.StatusUnauthorized, map[string]string{"message": "Bad credentials"})
		return
	}
	deviceJSON(w, http.StatusOK, map[string]any{"id": u.ID, "login": u.Login, "type": "User"})
}

// origin is the scheme and host the request came to: the simulator's own,
// where its sign-in page is.
func origin(r *http.Request) string {
	if r.TLS != nil {
		return "https://" + r.Host
	}
	return "http://" + r.Host
}

// appToken reads a check or revoke of a user access token, as GitHub does:
// the path's client id with the sign-in App's secret as Basic credentials,
// and {"access_token"} in the body. ok is false once it has answered.
func (s *Server) appToken(w http.ResponseWriter, r *http.Request) (token string, ok bool) {
	id, secret, basic := r.BasicAuth()
	if s.device.clientID == "" || !basic || id != r.PathValue("client_id") || id != s.device.clientID || secret != s.device.secret {
		deviceJSON(w, http.StatusUnauthorized, map[string]string{"message": "Requires authentication"})
		return "", false
	}
	var in struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.UnmarshalRead(r.Body, &in); err != nil || in.AccessToken == "" {
		deviceJSON(w, http.StatusUnprocessableEntity, map[string]string{"message": "Invalid request"})
		return "", false
	}
	if _, known := s.device.users[in.AccessToken]; !known {
		deviceJSON(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
		return "", false
	}
	return in.AccessToken, true
}

// checkToken answers POST /applications/{client_id}/token: the account a
// token the sign-in App issued belongs to. Any other token is 404.
func (s *Server) checkToken(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.appToken(w, r)
	if !ok {
		return
	}
	u := s.device.users[token]
	deviceJSON(w, http.StatusOK, map[string]any{
		"app":  map[string]any{"client_id": s.device.clientID},
		"user": map[string]any{"id": u.ID, "login": u.Login, "type": "User"},
	})
}

// revokeToken answers DELETE /applications/{client_id}/token: the token
// stops working.
func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.appToken(w, r)
	if !ok {
		return
	}
	delete(s.device.users, token)
	w.WriteHeader(http.StatusNoContent)
}

// Revoked reports whether a user access token no longer works (it was
// revoked, or never issued).
func (s *Server) Revoked(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, known := s.device.users[token]
	return !known
}

// ErrNoDeviceCode: no pending sign-in has that user code.
var ErrNoDeviceCode = errors.New("github sim: no pending sign-in with that code")

// AuthorizeDevice signs in as u for the pending sign-in whose user code is
// userCode, as a person does at github.com/login/device.
func (s *Server) AuthorizeDevice(userCode string, u DeviceUser) error {
	return s.decide(userCode, func(c *deviceCode) { c.signedIn = &u })
}

// SignInAs signs every later device code in as u at once, with polls every
// second: a person who signs in straight away (demos and tests).
func (s *Server) SignInAs(u DeviceUser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.device.auto = &u
}

// DenyDevice refuses the pending sign-in whose user code is userCode.
func (s *Server) DenyDevice(userCode string) error {
	return s.decide(userCode, func(c *deviceCode) { c.denied = true })
}

func (s *Server) decide(userCode string, f func(*deviceCode)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.device.codes {
		if c.user == userCode && !c.issued && c.signedIn == nil && !c.denied {
			f(c)
			return nil
		}
	}
	return ErrNoDeviceCode
}
