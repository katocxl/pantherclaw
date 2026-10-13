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

// GitHub sign-in through a GitHub App's device flow (G0 M8 P2f), as GitHub
// serves it: pclaw github link asks for a device code, a person enters the
// user code at GitHub and signs in, and pclaw polls for a user access
// token; GET /user says which account the token belongs to. In the
// simulator a test says who signs in with AuthorizeDevice.

// deviceExpiry is how long a device code lives (GitHub: 15 minutes).
const deviceExpiry = 15 * time.Minute

// deviceGrant is the device flow's grant type (RFC 8628).
const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

// DeviceUser is the GitHub account a person signs in as.
type DeviceUser struct {
	ID    int64
	Login string
}

// deviceState is the simulator's device codes and the user tokens they
// became.
type deviceState struct {
	codes map[string]*deviceCode // by device code
	users map[string]DeviceUser  // user access token → account
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

// deviceCode starts a sign-in for the registered App's client id.
func (s *Server) deviceCode(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clientID == "" || r.PostFormValue("client_id") != s.clientID {
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
		"device_code": code, "user_code": user, "verification_uri": "https://github.com/login/device",
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
	case s.clientID == "" || r.PostFormValue("client_id") != s.clientID:
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
