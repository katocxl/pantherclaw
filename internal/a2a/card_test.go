// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2a

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"net/http"
	"strings"
	"testing"
)

const testCard = `{
  "name": "Refund helper",
  "description": "Handles refunds (SIMULATED)",
  "version": "1.0.0",
  "supportedInterfaces": [
    {"url": "https://peer.example/a2a/v1", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
    {"url": "https://peer.example/a2a/rest", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"},
    {"url": "https://peer.example/a2a/grpc", "protocolBinding": "GRPC", "protocolVersion": "1.0"}
  ],
  "capabilities": {"streaming": true, "pushNotifications": true},
  "securitySchemes": {"bearer": {"httpAuthSecurityScheme": {"scheme": "Bearer"}}},
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["text/plain"],
  "skills": [
    {"id": "refunds", "name": "Refunds", "description": "Refund a payment", "tags": ["payments"]},
    {"id": "echo", "name": "Echo", "description": "Echo", "tags": []}
  ]
}`

func ed25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func p256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func keysOf(t *testing.T, pubs map[string]crypto.PublicKey) Keys {
	t.Helper()
	raw, err := PublicJWKS(pubs)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseKeys(raw)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestCardSignatures(t *testing.T) {
	ed, ec := ed25519Key(t), p256Key(t)
	keys := keysOf(t, map[string]crypto.PublicKey{"ed": ed.Public(), "ec": ec.Public()})
	for name, signer := range map[string]crypto.Signer{"ed": ed, "ec": ec} {
		t.Run(name, func(t *testing.T) {
			signed, err := Sign([]byte(testCard), name, signer)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifySignatures(signed, keys); err != nil {
				t.Fatalf("signed card: %v", err)
			}
			// Any change to what is signed breaks every signature.
			tampered := strings.Replace(string(signed), "Handles refunds", "Handles transfers", 1)
			if err := VerifySignatures([]byte(tampered), keys); !errors.Is(err, ErrCardSignature) {
				t.Fatalf("tampered card: %v, want ErrCardSignature", err)
			}
			// A key of another id does not count.
			other := keysOf(t, map[string]crypto.PublicKey{name: ed25519Key(t).Public()})
			if err := VerifySignatures(signed, other); !errors.Is(err, ErrCardSignature) {
				t.Fatalf("other key: %v, want ErrCardSignature", err)
			}
			// A signed card with no pinned keys cannot be verified.
			if err := VerifySignatures(signed, nil); !errors.Is(err, ErrCardKeysRequired) {
				t.Fatalf("no keys: %v, want ErrCardKeysRequired", err)
			}
		})
	}
	// Pinned keys and a card whose signatures were stripped.
	if err := VerifySignatures([]byte(testCard), keys); !errors.Is(err, ErrCardUnsigned) {
		t.Fatalf("stripped card: %v, want ErrCardUnsigned", err)
	}
	if err := VerifySignatures([]byte(testCard), nil); err != nil {
		t.Fatalf("unsigned card, no keys: %v", err)
	}
}

func TestCardSignatureAlgorithmMatchesKey(t *testing.T) {
	ec := p256Key(t)
	signed, err := Sign([]byte(testCard), "k", ec)
	if err != nil {
		t.Fatal(err)
	}
	// The same kid pinned as an Ed25519 key: ES256 never verifies with it.
	keys := keysOf(t, map[string]crypto.PublicKey{"k": ed25519Key(t).Public()})
	if err := VerifySignatures(signed, keys); !errors.Is(err, ErrCardSignature) {
		t.Fatalf("alg/key mismatch: %v", err)
	}
}

func TestCardSigningPayloadIgnoresDefaultsAndFormatting(t *testing.T) {
	ed := ed25519Key(t)
	signed, err := Sign([]byte(testCard), "ed", ed)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(signed, &m); err != nil {
		t.Fatal(err)
	}
	// A default-valued member added and the members reordered: same payload.
	m["iconUrl"] = ""
	m["capabilities"].(map[string]any)["extendedAgentCard"] = false
	re, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignatures(re, keysOf(t, map[string]crypto.PublicKey{"ed": ed.Public()})); err != nil {
		t.Fatalf("defaults added: %v", err)
	}
}

func TestParseKeysRefusesOtherKeys(t *testing.T) {
	for name, raw := range map[string]string{
		"rsa":       `{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"a"}]}`,
		"no kid":    `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}`,
		"duplicate": `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"a"},{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"a"}]}`,
		"empty":     `{"keys":[]}`,
		"wrong alg": `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"a","alg":"ES256"}]}`,
	} {
		if _, err := ParseKeys([]byte(raw)); !errors.Is(err, ErrKeysInvalid) {
			t.Errorf("%s: %v, want ErrKeysInvalid", name, err)
		}
	}
}

func TestCheckPin(t *testing.T) {
	raw := []byte(testCard)
	if _, err := CheckPin(raw, nil, BindingJSONRPC, "https://peer.example/a2a/v1", []string{"refunds"}); err != nil {
		t.Fatalf("pin: %v", err)
	}
	for name, c := range map[string]struct {
		binding, url string
		skills       []string
		want         error
	}{
		"grpc":            {BindingGRPC, "https://peer.example/a2a/grpc", nil, ErrInterface},
		"undeclared url":  {BindingJSONRPC, "https://evil.example/a2a/v1", nil, ErrInterface},
		"binding mixup":   {BindingHTTPJSON, "https://peer.example/a2a/v1", nil, ErrInterface},
		"undeclared skil": {BindingJSONRPC, "https://peer.example/a2a/v1", []string{"transfers"}, ErrSkill},
	} {
		if _, err := CheckPin(raw, nil, c.binding, c.url, c.skills); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	for name, bad := range map[string]string{
		"not json":      `{`,
		"no interfaces": `{"name":"x","supportedInterfaces":[]}`,
		"duplicate":     `{"name":"x","name":"y","supportedInterfaces":[{"url":"https://a","protocolBinding":"JSONRPC"}]}`,
	} {
		if _, err := CheckPin([]byte(bad), nil, BindingJSONRPC, "https://a", nil); !errors.Is(err, ErrCardInvalid) {
			t.Errorf("%s: %v, want ErrCardInvalid", name, err)
		}
	}
}

func TestDigestIsCanonical(t *testing.T) {
	a, err := Digest([]byte(`{"b":1,"a":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Digest([]byte("{ \"a\" : \"x\",\n \"b\": 1.0 }"))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := Digest([]byte(`{"a":"x","b":2}`))
	if a != b || a == c {
		t.Fatalf("digest not canonical: %x %x %x", a, b, c)
	}
}

func TestRewrite(t *testing.T) {
	signed, err := Sign([]byte(testCard), "ed", ed25519Key(t))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Rewrite(signed, BindingHTTPJSON, "https://gw.example/a2a/peer", []string{"refunds"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCard(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Signatures) != 0 || len(c.SecuritySchemes) != 0 || c.Capabilities.PushNotifications {
		t.Fatalf("rewritten card keeps signatures, schemes or push: %s", out)
	}
	if len(c.SupportedInterfaces) != 1 || c.SupportedInterfaces[0].URL != "https://gw.example/a2a/peer" ||
		c.SupportedInterfaces[0].ProtocolBinding != BindingHTTPJSON {
		t.Fatalf("interfaces: %+v", c.SupportedInterfaces)
	}
	if ids := c.SkillIDs(); len(ids) != 1 || ids[0] != "refunds" {
		t.Fatalf("skills: %v", ids)
	}
}

func TestRoute(t *testing.T) {
	for _, c := range []struct {
		method, path, want, id string
	}{
		{http.MethodPost, "/message:send", MethodSendMessage, ""},
		{http.MethodPost, "/message:stream", MethodSendStreamingMessage, ""},
		{http.MethodGet, "/tasks", MethodListTasks, ""},
		{http.MethodGet, "/tasks/t-1", MethodGetTask, "t-1"},
		{http.MethodPost, "/tasks/t-1:cancel", MethodCancelTask, "t-1"},
		{http.MethodPost, "/tasks/t-1:subscribe", MethodSubscribeToTask, "t-1"},
		{http.MethodPost, "/tasks/t-1/pushNotificationConfigs", MethodCreatePushConfig, "t-1"},
		{http.MethodGet, "/tasks/t-1/pushNotificationConfigs/c", MethodGetPushConfig, "t-1"},
		{http.MethodGet, "/extendedAgentCard", MethodGetExtendedCard, ""},
	} {
		got, id, ok := Route(c.method, c.path)
		if !ok || got != c.want || id != c.id {
			t.Errorf("%s %s = %q %q %v", c.method, c.path, got, id, ok)
		}
		if !Unsupported(got) {
			hm, p, ok := Path(got, id)
			if !ok || hm != c.method || p != c.path {
				t.Errorf("Path(%s) = %s %s %v", got, hm, p, ok)
			}
		}
	}
	for _, bad := range [][2]string{
		{http.MethodGet, "/message:send"},
		{http.MethodDelete, "/tasks/t"},
		{http.MethodPost, "/tasks/t:delete"},
		{http.MethodGet, "/tasks/"},
		{http.MethodGet, "/tasks/a%2fb"},
		{http.MethodPost, "/other"},
	} {
		if m, _, ok := Route(bad[0], bad[1]); ok {
			t.Errorf("%s %s routed to %s", bad[0], bad[1], m)
		}
	}
}
