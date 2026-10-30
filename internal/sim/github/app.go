// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package github

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Token lifetimes and the App JWT limits GitHub enforces.
const (
	tokenLifetime = time.Hour
	maxJWTAhead   = 10 * time.Minute
	jwtSkew       = 60 * time.Second
)

// verifyJWT checks an App JWT (RS256 over the App's key) and its time
// claims as GitHub does: expires in the future but at most 10 minutes
// ahead, issued no later than now plus a minute, issued by the App's id or
// client id.
func (s *Server) verifyJWT(raw string) (AppJWT, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(s.liveKeys()) == 0 {
		return AppJWT{}, errors.New("malformed")
	}
	var head struct {
		Alg string `json:"alg"`
	}
	if err := decodeSegment(parts[0], &head); err != nil || head.Alg != "RS256" {
		return AppJWT{}, errors.New("unsupported algorithm")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return AppJWT{}, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := s.verifySignature(sum[:], sig); err != nil {
		return AppJWT{}, err
	}
	var c struct {
		Iss jsontext.Value `json:"iss"`
		Iat int64          `json:"iat"`
		Exp int64          `json:"exp"`
	}
	if err := decodeSegment(parts[1], &c); err != nil {
		return AppJWT{}, err
	}
	iss := strings.Trim(string(c.Iss), `"`)
	now := s.now()
	iat, exp := time.Unix(c.Iat, 0), time.Unix(c.Exp, 0)
	switch {
	case iss != strconv.FormatInt(s.appID, 10) && iss != s.clientID:
		return AppJWT{}, errors.New("unknown issuer")
	case !exp.After(now) || exp.Sub(now) > maxJWTAhead:
		return AppJWT{}, errors.New("'Expiration time' claim ('exp') is outside the allowed range")
	case iat.After(now.Add(jwtSkew)):
		return AppJWT{}, errors.New("'Issued at' claim ('iat') must be an Integer representing a time in the past")
	}
	return AppJWT{Issuer: iss, IssuedAt: iat, Expires: exp}, nil
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// accessToken mints an installation token (POST
// /app/installations/{id}/access_tokens) for the repositories and
// permissions asked for, which must be within the installation's; with
// neither, the token gets everything the installation has, as on GitHub.
// Repositories are named (repositories) or given by id (repository_ids).
func (s *Server) accessToken(w http.ResponseWriter, r *http.Request) {
	if status := s.tokenFault(w); status != 0 {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.requests = append(s.requests, Request{Method: r.Method, Path: r.URL.Path, Write: true, Status: status})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := Request{Method: r.Method, Path: r.URL.Path, Write: true}
	rec.Status = s.mint(w, r, &rec)
	s.requests = append(s.requests, rec)
}

func (s *Server) mint(w http.ResponseWriter, r *http.Request, rec *Request) int {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return fail(w, http.StatusUnauthorized, "A JSON web token could not be decoded")
	}
	jwt, err := s.verifyJWT(bearer)
	if err != nil {
		return fail(w, http.StatusUnauthorized, err.Error())
	}
	s.jwts = append(s.jwts, jwt)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	in := s.installs[id]
	if in == nil {
		return fail(w, http.StatusNotFound, "Not Found")
	}
	rec.Installation = id
	var body struct {
		Repositories  []string          `json:"repositories"`
		RepositoryIDs []int64           `json:"repository_ids"`
		Permissions   map[string]string `json:"permissions"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if len(raw) > 0 && json.Unmarshal(raw, &body, json.RejectUnknownMembers(true)) != nil {
		return fail(w, http.StatusUnprocessableEntity, "Invalid request")
	}
	const notAccessible = "There is at least one repository that does not exist or is not accessible to the parent installation."
	names := slices.Clone(body.Repositories)
	for _, rid := range body.RepositoryIDs {
		i := slices.IndexFunc(in.Repos, func(n string) bool { return accountID(in.Account+"/"+n) == rid })
		if i < 0 {
			return fail(w, http.StatusUnprocessableEntity, notAccessible)
		}
		names = append(names, in.Repos[i])
	}
	if (body.Repositories == nil && body.RepositoryIDs == nil) || s.faults.WiderGrant {
		names = in.Repos
	}
	repos := make([]string, 0, len(names))
	for _, n := range names {
		if !slices.Contains(in.Repos, strings.ToLower(n)) {
			return fail(w, http.StatusUnprocessableEntity, notAccessible)
		}
		if full := in.Account + "/" + strings.ToLower(n); !slices.Contains(repos, full) {
			repos = append(repos, full)
		}
	}
	perms := body.Permissions
	if perms == nil || s.faults.WiderGrant {
		perms = in.Permissions
	}
	for name, level := range perms {
		if !covers(in.Permissions[name], level) {
			return fail(w, http.StatusUnprocessableEntity, "The permissions requested are not granted to this installation.")
		}
	}
	// Every token may read metadata, and GitHub lists it among the
	// token's permissions whatever was asked for.
	perms = maps.Clone(perms)
	if perms == nil {
		perms = map[string]string{}
	}
	if perms["metadata"] == "" {
		perms["metadata"] = "read"
	}
	t := &Token{value: randomToken(), Installation: id, Repos: repos, Permissions: perms, Expires: s.now().Add(tokenLifetime)}
	s.tokens[t.value] = t
	rec.Token, rec.Repos, rec.Permissions = Fingerprint(t.value), slices.Clone(repos), maps.Clone(perms)
	list := make([]map[string]any, len(repos))
	for i, full := range repos {
		list[i] = map[string]any{"id": accountID(full), "name": full[strings.IndexByte(full, '/')+1:], "full_name": full}
	}
	return reply(w, http.StatusCreated, map[string]any{
		"token": t.value, "expires_at": t.Expires.UTC().Format(time.RFC3339), "permissions": maps.Clone(perms),
		"repository_selection": "selected", "repositories": list, "simulated": true,
	})
}

// revoke revokes the installation token the request carries (DELETE
// /installation/token).
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := Request{Method: r.Method, Path: r.URL.Path, Write: true}
	t, _ := s.authenticate(r)
	switch {
	case t == nil:
		rec.Status = fail(w, http.StatusUnauthorized, "Bad credentials")
	case t.Installation == 0:
		rec.Status = fail(w, http.StatusForbidden, "Only installation tokens can be revoked here")
	case s.faults.RevokeStatus != 0:
		rec.Status = fail(w, s.faults.RevokeStatus, "Revocation failed")
	default:
		t.Revoked = true
		rec.Token, rec.Installation, rec.Repos, rec.Permissions = Fingerprint(t.value), t.Installation, slices.Clone(t.Repos), maps.Clone(t.Permissions)
		w.WriteHeader(http.StatusNoContent)
		rec.Status = http.StatusNoContent
	}
	s.requests = append(s.requests, rec)
}

// AddAppKey adds another private key to the App, as its settings allow
// (G0 M20 S20c): its JWTs are accepted as the registered key's are.
func (s *Server) AddAppKey(key *rsa.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, key)
}

// RevokeAppKey deletes one of the App's keys, as a person does in its
// settings: its JWTs are refused from then on (401), unless the
// KeepRevokedKeys fault holds.
func (s *Server) RevokeAppKey(key *rsa.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked = append(s.revoked, key)
}

// liveKeys are the App's keys whose JWTs are accepted.
func (s *Server) liveKeys() []*rsa.PublicKey {
	var out []*rsa.PublicKey
	for _, k := range append([]*rsa.PublicKey{s.appKey}, s.keys...) {
		if k == nil {
			continue
		}
		if !s.faults.KeepRevokedKeys && slices.ContainsFunc(s.revoked, func(r *rsa.PublicKey) bool { return r.Equal(k) }) {
			continue
		}
		out = append(out, k)
	}
	return out
}

// verifySignature checks an RS256 signature against the App's live keys.
func (s *Server) verifySignature(sum, sig []byte) error {
	err := errors.New("no key")
	for _, k := range s.liveKeys() {
		if err = rsa.VerifyPKCS1v15(k, crypto.SHA256, sum, sig); err == nil {
			return nil
		}
	}
	return err
}

// app answers GET /app for the App's JWT: the App's id and client id, as
// GitHub names the App a key belongs to. A deleted key's JWT gets 401.
func (s *Server) app(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := Request{Method: r.Method, Path: r.URL.Path}
	rec.Status = s.describeApp(w, r)
	s.requests = append(s.requests, rec)
}

func (s *Server) describeApp(w http.ResponseWriter, r *http.Request) int {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return fail(w, http.StatusUnauthorized, "A JSON web token could not be decoded")
	}
	jwt, err := s.verifyJWT(bearer)
	if err != nil {
		return fail(w, http.StatusUnauthorized, err.Error())
	}
	s.jwts = append(s.jwts, jwt)
	if s.faults.AppStatus != 0 {
		return fail(w, s.faults.AppStatus, "Simulated app endpoint failure")
	}
	return reply(w, http.StatusOK, map[string]any{
		"id": s.appID, "client_id": s.clientID, "slug": "pantherclaw-sim", "name": "PantherClaw (simulated)", "simulated": true,
	})
}
