// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"slices"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const (
	fuzzRPID   = "pc.example.test"
	fuzzOrigin = "https://pc.example.test"
)

// ceremonyRow is the stored ceremony a SessionData stands for, as
// storeCeremony writes it and ConsumeCeremony reads it back.
func ceremonyRow(t testing.TB, sd *webauthn.SessionData) dbq.ConsumeCeremonyRow {
	t.Helper()
	raw, err := decodeChallenge(sd.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	return dbq.ConsumeCeremonyRow{Challenge: raw, AllowedCredentials: sd.AllowedCredentialIDs, ExpiresAt: time.Now().Add(time.Hour)}
}

// clientResponse is the part of a browser's PublicKeyCredential JSON the
// fuzzer replaces.
type clientResponse struct {
	Response map[string]any `json:"response"`
}

// withResponse returns resp with response fields replaced (base64url).
func withResponse(t *testing.T, resp []byte, fields map[string][]byte) []byte {
	t.Helper()
	var r map[string]any
	if err := json.Unmarshal(resp, &r); err != nil {
		t.Fatal(err)
	}
	inner, _ := r["response"].(map[string]any)
	for k, v := range fields {
		inner[k] = base64.RawURLEncoding.EncodeToString(v)
	}
	out, err := json.Marshal(r, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func responseField(t testing.TB, resp []byte, name string) []byte {
	t.Helper()
	var r clientResponse
	if err := json.Unmarshal(resp, &r, json.RejectUnknownMembers(false)); err != nil {
		t.Fatal(err)
	}
	s, _ := r.Response[name].(string)
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// finishStepUp applies FinishStepUp's checks without the database: the
// size cap, parsing, the library's verification against the session data
// rebuilt from the stored ceremony, user verification, a key of the user,
// and the counter (HR-153, HR-154).
func (w *WebAuthn) finishStepUp(u *waUser, row dbq.ConsumeCeremonyRow, response []byte) error {
	if len(response) > maxResponseBytes {
		return ErrWebAuthnFailed
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return err
	}
	c, err := w.wa.ValidateLogin(u, w.sessionData(u.id, row, false), parsed)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(u.credentials, func(x webauthn.Credential) bool { return bytes.Equal(x.ID, c.ID) })
	switch {
	case !c.Flags.UserVerified, i < 0:
		return ErrWebAuthnFailed
	case !CounterOK(u.counts[i], parsed.Response.AuthenticatorData.Counter):
		return ErrCredentialSuspended
	}
	return nil
}

// finishRegistration applies FinishRegistration's checks without the
// database, and returns what was parsed.
func (w *WebAuthn) finishRegistration(u *waUser, row dbq.ConsumeCeremonyRow, response []byte) (*protocol.ParsedCredentialCreationData, error) {
	if len(response) > maxResponseBytes {
		return nil, ErrWebAuthnFailed
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, err
	}
	c, err := w.wa.CreateCredential(u, w.sessionData(u.id, row, true), parsed)
	if err != nil {
		return nil, err
	}
	if !c.Flags.UserVerified {
		return nil, ErrWebAuthnFailed
	}
	if _, err := checkKey(c.PublicKey); err != nil {
		return nil, err
	}
	return parsed, nil
}

// FuzzWebAuthnFinish (G0 M5 part 1, HR-153): random client data and
// authenticator data never panic the finish of a ceremony and never
// verify. A step-up assertion passes the relying party's checks (this
// server's RP id and origin, the ceremony's challenge, required user
// verification, a key of the user, a counter that moves) only with the
// exact bytes the key signed. A registration response, which attestation
// "none" leaves unsigned, passes only for a webauthn.create of this
// ceremony's challenge from this origin, this RP id's hash, user
// verification and an allowed algorithm.
func FuzzWebAuthnFinish(f *testing.F) {
	w, err := NewWebAuthn(nil, WebAuthnConfig{RPID: fuzzRPID, PublicURL: fuzzOrigin}, nil, clock.System{}, nil)
	if err != nil {
		f.Fatal(err)
	}
	key, err := webauthntest.New(fuzzOrigin, fuzzRPID, webauthntest.ES256)
	if err != nil {
		f.Fatal(err)
	}
	id := ids.NewV7()
	user := func() *waUser { return &waUser{id: id, name: "dev@example.test"} }

	// Registration: the ceremony as BeginRegistration starts it.
	creation, regSD, err := w.wa.BeginRegistration(user(), webauthn.WithCredentialParameters(credentialParams()))
	if err != nil {
		f.Fatal(err)
	}
	opts, err := json.Marshal(creation)
	if err != nil {
		f.Fatal(err)
	}
	reg, err := key.Register(opts)
	if err != nil {
		f.Fatal(err)
	}
	regRow := ceremonyRow(f, regSD)
	parsed, err := w.finishRegistration(user(), regRow, reg)
	if err != nil {
		f.Fatalf("the authenticator's own registration does not verify: %v", err)
	}
	cred, err := w.wa.CreateCredential(user(), w.sessionData(id, regRow, true), parsed)
	if err != nil {
		f.Fatal(err)
	}
	registered := func() *waUser {
		u := user()
		u.credentials, u.rowIDs, u.counts = []webauthn.Credential{*cred}, []ids.UUID{id}, []uint32{cred.Authenticator.SignCount}
		return u
	}

	// Step-up: the ceremony as BeginStepUp starts it.
	assertion, loginSD, err := w.wa.BeginLogin(registered(), webauthn.WithAllowedCredentials(descriptors(registered().credentials)),
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		f.Fatal(err)
	}
	if opts, err = json.Marshal(assertion); err != nil {
		f.Fatal(err)
	}
	signed, err := key.Assert(opts)
	if err != nil {
		f.Fatal(err)
	}
	loginRow := ceremonyRow(f, loginSD)
	if err := w.finishStepUp(registered(), loginRow, signed); err != nil {
		f.Fatalf("the authenticator's own assertion does not verify: %v", err)
	}
	signedCDJ, signedAuth := responseField(f, signed, "clientDataJSON"), responseField(f, signed, "authenticatorData")
	regCDJ, regAtt := responseField(f, reg, "clientDataJSON"), responseField(f, reg, "attestationObject")

	f.Add(false, signedCDJ, signedAuth)
	f.Add(false, bytes.Replace(signedCDJ, []byte(fuzzOrigin), []byte("https://evil.example"), 1), signedAuth)
	f.Add(false, signedCDJ, append(slices.Clone(signedAuth[:32]), 0x01, 0, 0, 0, 9)) // user present only, counter 9
	f.Add(false, []byte(`{"type":"webauthn.get"}`), []byte{})
	f.Add(true, regCDJ, regAtt)
	f.Add(true, bytes.Replace(regCDJ, []byte("webauthn.create"), []byte("webauthn.get"), 1), regAtt)
	f.Add(true, []byte(`{}`), []byte{0xa0})
	rpHash := sha256.Sum256([]byte(fuzzRPID))
	f.Fuzz(func(t *testing.T, registration bool, clientData, authData []byte) {
		if !registration {
			resp := withResponse(t, signed, map[string][]byte{"clientDataJSON": clientData, "authenticatorData": authData})
			err := w.finishStepUp(registered(), loginRow, resp)
			if err == nil && (!bytes.Equal(clientData, signedCDJ) || !bytes.Equal(authData, signedAuth)) {
				t.Fatalf("an assertion over other bytes verified:\nclient data %q\nauthenticator data %x", clientData, authData)
			}
			return
		}
		resp := withResponse(t, reg, map[string][]byte{"clientDataJSON": clientData, "attestationObject": authData})
		p, err := w.finishRegistration(user(), regRow, resp)
		if err != nil {
			return
		}
		cd, ad := p.Response.CollectedClientData, p.Response.AttestationObject.AuthData
		if cd.Type != protocol.CreateCeremony || cd.Origin != fuzzOrigin || cd.Challenge != regSD.Challenge ||
			!bytes.Equal(ad.RPIDHash, rpHash[:]) || !ad.Flags.HasUserVerified() {
			t.Fatalf("a registration verified for type %q, origin %q, challenge %q, RP hash %x, flags %08b",
				cd.Type, cd.Origin, cd.Challenge, ad.RPIDHash, ad.Flags)
		}
	})
}
