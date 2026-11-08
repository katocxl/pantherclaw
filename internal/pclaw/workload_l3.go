// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/go-jose/go-jose/v4"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// L3 attestation sources (PAP-1 §3.3, G0 M35 D1030): the evidence binds
// the org, the nonce of the request it travels with and the thumbprint of
// the workload key. pclaw first sends that same request without a nonce
// (the standard use_nonce challenge, D1030a), then builds the evidence for
// the nonce the server returned and sends the request for real.

// l3Flags declares --attest and the SVID files.
type l3Flags struct {
	attest   *string
	svidCert *string
	svidKey  *string
	// src is the request the evidence binds; set by bindTo.
	src *l3Source
}

// l3Request returns the procedure URL and the real request, without the
// L3 attestation, for the use_nonce challenge.
// placeholder builds evidence with an empty nonce, for a request whose
// org only the attestation names (an Enroll without an enrollment token);
// the server refuses the challenge with use_nonce before it reads it.
type l3Request func(ctx context.Context, placeholder func() (*pantherclawv1.Attestation, error)) (string, proto.Message, error)

type l3Source struct {
	t       *workloadclient.Transport
	jkt     string
	request l3Request
}

func declareL3(fs *flag.FlagSet) l3Flags {
	return l3Flags{
		attest: fs.String("attest", "", "L3: attest with spiffe-x509 (an X.509-SVID signs this request's key and nonce) "+
			"or gcp-instance (a GCE identity token bound to this request's key and nonce)"),
		svidCert: fs.String("svid-cert", "", "with --attest spiffe-x509: the X.509-SVID chain (PEM, leaf first); read again at each renewal"),
		svidKey:  fs.String("svid-key", "", "with --attest spiffe-x509: the SVID's private key (PEM); read again at each renewal"),
		src:      &l3Source{},
	}
}

// set reports whether an L3 source is chosen.
func (f l3Flags) set() bool { return f.attest != nil && *f.attest != "" }

// check refuses an unknown --attest value and SVID files without
// spiffe-x509.
func (f l3Flags) check() error {
	if f.attest == nil {
		return nil
	}
	switch *f.attest {
	case "":
		if *f.svidCert != "" || *f.svidKey != "" {
			return errors.New("--svid-cert and --svid-key need --attest spiffe-x509")
		}
	case "spiffe-x509":
		if *f.svidCert == "" || *f.svidKey == "" {
			return errors.New("--attest spiffe-x509 needs --svid-cert and --svid-key")
		}
	case "gcp-instance":
		if *f.svidCert != "" || *f.svidKey != "" {
			return errors.New("--svid-cert and --svid-key are only for --attest spiffe-x509")
		}
	default:
		return errors.New("--attest must be spiffe-x509 or gcp-instance")
	}
	return nil
}

// bindTo names the transport (whose nonce the evidence binds), the
// workload key, and the real request the challenge repeats.
func (f l3Flags) bindTo(t *workloadclient.Transport, kf workloadclient.KeyFile, request l3Request) {
	if f.src == nil || t == nil {
		return
	}
	key, err := kf.Key()
	if err != nil {
		return
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	*f.src = l3Source{t: t, jkt: jws.Thumbprint(pub), request: request}
}

// attestation challenges the real request for org's current nonce and
// builds the L3 evidence bound to it.
func (f l3Flags) attestation(ctx context.Context, a *app, org ids.OrgID) (*pantherclawv1.Attestation, error) {
	if org.IsZero() {
		return nil, errors.New("the org is unknown: pass --org")
	}
	if f.src == nil || f.src.t == nil || f.src.jkt == "" || f.src.request == nil {
		return nil, errors.New("internal: the L3 attestation has no request to bind")
	}
	bind := issuers.L3Bind{Org: org, JKT: f.src.jkt}
	url, msg, err := f.src.request(ctx, func() (*pantherclawv1.Attestation, error) { return f.build(ctx, a, bind) })
	if err != nil {
		return nil, err
	}
	body, err := protojson.Marshal(msg)
	if err != nil {
		return nil, err
	}
	if bind.Nonce, err = f.src.t.Challenge(ctx, url, body); err != nil {
		return nil, fmt.Errorf("asking the server for a nonce: %w", err)
	}
	return f.build(ctx, a, bind)
}

// build makes the evidence for bind.
func (f l3Flags) build(ctx context.Context, a *app, bind issuers.L3Bind) (*pantherclawv1.Attestation, error) {
	switch *f.attest {
	case "spiffe-x509":
		tok, err := svidSign(*f.svidCert, *f.svidKey, bind.String())
		if err != nil {
			return nil, err
		}
		return &pantherclawv1.Attestation{Kind: pantherclawv1.AttestationKind_ATTESTATION_KIND_SPIFFE_X509, Token: tok}, nil
	case "gcp-instance":
		tok, err := gcpIdentity(ctx, a, bind.Audience())
		if err != nil {
			return nil, err
		}
		return &pantherclawv1.Attestation{Kind: pantherclawv1.AttestationKind_ATTESTATION_KIND_GCP_INSTANCE, Token: tok}, nil
	}
	return nil, errors.New("--attest must be spiffe-x509 or gcp-instance")
}

// svidSign signs payload with the SVID key as a compact JWS whose x5c
// header carries the SVID chain (leaf first).
func svidSign(certFile, keyFile, payload string) (string, error) {
	certPEM, err := os.ReadFile(certFile) //nolint:gosec // G304: the workload's own file
	if err != nil {
		return "", err
	}
	var x5c []string
	for rest := certPEM; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			x5c = append(x5c, base64.StdEncoding.EncodeToString(b.Bytes))
		}
	}
	if len(x5c) == 0 || len(x5c) > 4 {
		return "", fmt.Errorf("%s must hold the SVID chain (1 to 4 PEM certificates, leaf first)", certFile)
	}
	keyPEM, err := os.ReadFile(keyFile) //nolint:gosec // G304: the workload's own file
	if err != nil {
		return "", err
	}
	key, err := parseSVIDKey(keyPEM)
	if err != nil {
		return "", fmt.Errorf("%s: %w", keyFile, err)
	}
	var alg jose.SignatureAlgorithm
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			alg = jose.ES256
		case elliptic.P384():
			alg = jose.ES384
		default:
			return "", errors.New("the SVID key must be ECDSA P-256 or P-384, RSA or Ed25519")
		}
	case *rsa.PrivateKey:
		alg = jose.PS256
	case ed25519.PrivateKey:
		alg = jose.EdDSA
	default:
		return "", errors.New("the SVID key must be ECDSA P-256 or P-384, RSA or Ed25519")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithHeader("x5c", x5c))
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign([]byte(payload))
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// parseSVIDKey reads a PKCS #8, SEC 1 or PKCS #1 private key.
func parseSVIDKey(raw []byte) (crypto.Signer, error) {
	b, _ := pem.Decode(raw)
	if b == nil {
		return nil, errors.New("no PEM private key")
	}
	if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
	}
	if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key")
}

// issueTokenChallenge is the use_nonce challenge of an IssueToken for the
// instance: req as it will be sent, without the attestation (G0 M35
// D1030a). The identifier names the org.
func issueTokenChallenge(server string, req *pantherclawv1.IssueTokenRequest) l3Request {
	return func(context.Context, func() (*pantherclawv1.Attestation, error)) (string, proto.Message, error) {
		base, err := checkServer(server)
		if err != nil {
			return "", nil, err
		}
		challenge, _ := proto.Clone(req).(*pantherclawv1.IssueTokenRequest)
		challenge.Attestation = nil
		return base + pantherclawv1connect.WorkloadServiceIssueTokenProcedure, challenge, nil
	}
}
