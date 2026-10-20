// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"io/fs"
	"os"
	"strings"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	a2asim "github.com/katocxl/pantherclaw/internal/sim/a2a"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
)

// runA2A serves a simulated A2A 1.0 peer agent (G0 M14 D33).
func runA2A(ctx context.Context, args []string, stderr io.Writer) error {
	fl := flag.NewFlagSet("a2a", flag.ContinueOnError)
	fl.SetOutput(stderr)
	addr := fl.String("addr", "127.0.0.1:9093", "listen address (loopback)")
	base := fl.String("base-url", "", "the public base URL the card's interfaces point at (default: http://{Host} of each card request)")
	name := fl.String("name", "", "the agent's name on its card")
	tokenFile := fl.String("token-file", "", "file holding the bearer token every call must carry (the credential PantherClaw holds)")
	signKey := fl.String("sign-key", "", "sign the card with this Ed25519 key (PKCS#8 PEM; created when it does not exist)")
	jwksOut := fl.String("jwks-out", "", "with --sign-key, write the card's public JWKS here (to pin on the connection)")
	latency := fl.Duration("latency", 0, "added latency per request")
	completeAfter := fl.Duration("complete-after", 0, "how long a new task stays working before it ends")
	streamDelay := fl.Duration("stream-delay", 0, "pause between streamed events (a slow stream)")
	oversize := fl.Int("oversize", 0, "pad every task's answer to this many bytes")
	authRequired := fl.Bool("auth-required", false, "end every task in TASK_STATE_AUTH_REQUIRED")
	fail := fl.Bool("fail", false, "end every task in TASK_STATE_FAILED")
	description := fl.String("description", "", "replace the card's description (drift)")
	peerTokens := fl.Bool("require-peer-tokens", false, "act as a PantherClaw peer agent: require an action token naming a delegated run on every message (with --jwks-url and --audience)")
	jwksURL := fl.String("jwks-url", "", "the PantherClaw server's /.well-known/pantherclaw/jwks.json")
	audience := fl.String("audience", "", "the audience peer tokens must be addressed to: this agent's interface URL")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *jwksOut != "" && *signKey == "" {
		return errors.New("--jwks-out goes with --sign-key")
	}
	o := a2asim.Options{Name: *name, BaseURL: strings.TrimRight(*base, "/")}
	if *peerTokens {
		if *jwksURL == "" || *audience == "" {
			return errors.New("--require-peer-tokens needs --jwks-url and --audience")
		}
		o.VerifyPeer = a2asim.PeerVerifier(&payments.ActionVerifier{JWKSURL: *jwksURL, Audience: *audience})
	}
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		o.Token = strings.TrimSpace(string(b))
	}
	if *signKey != "" {
		key, err := cardKey(*signKey)
		if err != nil {
			return err
		}
		pub, ok := key.Public().(ed25519.PublicKey)
		if !ok {
			return errors.New("--sign-key: not an Ed25519 key")
		}
		o.SigningKey, o.KeyID = key, "sim-a2a-"+strings.ToLower(pubPrefix(pub))
		if *jwksOut != "" {
			raw, err := wire.PublicJWKS(map[string]crypto.PublicKey{o.KeyID: pub})
			if err != nil {
				return err
			}
			if err := os.WriteFile(*jwksOut, raw, 0o600); err != nil {
				return err
			}
		}
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := a2asim.New(o, a2asim.Faults{
		Latency: *latency, CompleteAfter: *completeAfter, StreamDelay: *streamDelay, OversizeBytes: *oversize,
		AuthRequired: *authRequired, Fail: *fail, Description: *description,
	}, log)
	return serve(ctx, *addr, sim.Handler(), log, "sim.a2a_listening")
}

// cardKey reads the card's Ed25519 key, or creates it (mode 0600) when the
// file does not exist.
func cardKey(path string) (crypto.Signer, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the file
	if errors.Is(err, fs.ErrNotExist) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		return key, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("--sign-key: not a PKCS#8 PEM file")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("--sign-key: not an Ed25519 key")
	}
	return s, nil
}

// pubPrefix is a short, stable key id part from the public key.
func pubPrefix(pub ed25519.PublicKey) string {
	const hex = "0123456789abcdef"
	var sb strings.Builder
	for _, b := range pub[:4] {
		sb.WriteByte(hex[b>>4])
		sb.WriteByte(hex[b&0xf])
	}
	return sb.String()
}
