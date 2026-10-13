// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchortest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// TSAURL is the URL the fake authority answers on.
const TSAURL = "https://tsa.test/api/v1/timestamp"

// TSANow is the fake authority's time (genTime).
var TSANow = time.Date(2026, 10, 10, 9, 0, 5, 0, time.UTC)

var (
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA1            = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidExtKeyUsage     = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidTimeStamping    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
)

// CA is a test certificate authority with a timestamping certificate.
type CA struct {
	Root    *x509.Certificate
	RootKey crypto.Signer
	Cert    *x509.Certificate
	CertKey crypto.Signer
	Chain   []*x509.Certificate // the signing certificate first, the root last
}

// CertOpts shapes the timestamping certificate.
type CertOpts struct {
	RSA         bool      // an RSA-2048 key instead of ECDSA P-256
	NoEKU       bool      // no extended key usage
	NonCritical bool      // the timeStamping EKU is not critical
	ExtraEKU    bool      // codeSigning besides timeStamping
	NotAfter    time.Time // default: 30 days after Now
	// Now bases the certificates' validity on another time than TSANow
	// (tests that timestamp with the real clock set Fault.GenTime too).
	Now time.Time
}

// NewCA returns a test authority: an ECDSA P-384 root and a timestamping
// certificate valid from an hour before TSANow (or o.Now).
func NewCA(t testing.TB, o CertOpts) *CA {
	t.Helper()
	now := TSANow
	if !o.Now.IsZero() {
		now = o.Now
	}
	rootKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test tsa root"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	var certKey crypto.Signer
	if o.RSA {
		certKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		certKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	notAfter := o.NotAfter
	if notAfter.IsZero() {
		notAfter = now.Add(30 * 24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "test tsa"},
		NotBefore: now.Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}
	if !o.NoEKU {
		ekus := []asn1.ObjectIdentifier{oidTimeStamping}
		if o.ExtraEKU {
			ekus = append(ekus, oidCodeSigning)
		}
		v, _ := asn1.Marshal(ekus)
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidExtKeyUsage, Critical: !o.NonCritical, Value: v}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, certKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &CA{Root: root, RootKey: rootKey, Cert: cert, CertKey: certKey, Chain: []*x509.Certificate{cert, root}}
}

// TSAFault breaks one part of the fake authority's answer.
type TSAFault struct {
	Status        int  // PKIStatus (0, granted, when unset)
	WrongNonce    bool // answers with another nonce
	NoNonce       bool
	WrongImprint  bool // timestamps other data
	SHA1Imprint   bool
	BadSignature  bool
	WrongDigest   bool // messageDigest attribute of other content
	NoSignedAttrs bool
	NoContentType bool
	TwoSigners    bool
	NoCerts       bool      // the token does not embed the signer's certificate
	GenTime       time.Time // default TSANow
}

// TSA is a local RFC 3161 authority: it parses the request and answers with
// a CMS SignedData token built by a small encoder (RFC 5652 §5).
type TSA struct {
	T     testing.TB
	CA    *CA
	Fault TSAFault
	// Calls counts requests; Request is the last request body.
	Calls   int
	Request []byte
}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	Nonce          *big.Int `asn1:"optional"`
	CertReq        bool     `asn1:"optional"`
}

type accuracy struct {
	Seconds int `asn1:"optional"`
}

type pkiStatusInfo struct {
	Status int
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

func (f *TSA) marshal(v any, params ...string) []byte {
	f.T.Helper()
	var (
		b   []byte
		err error
	)
	if len(params) > 0 {
		b, err = asn1.MarshalWithParams(v, params[0])
	} else {
		b, err = asn1.Marshal(v)
	}
	if err != nil {
		f.T.Fatal(err)
	}
	return b
}

func (f *TSA) setOf(elems ...[]byte) []byte {
	raws := make([]asn1.RawValue, 0, len(elems))
	for _, e := range elems {
		raws = append(raws, asn1.RawValue{FullBytes: e})
	}
	return f.marshal(raws, "set")
}

// wrap0 is a [0] wrapper; encoding/asn1 ignores `explicit` on a RawValue.
func wrap0(inner []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}
}

// Token builds a TimeStampToken (a DER ContentInfo) for the imprint and
// nonce, applying the configured fault.
func (f *TSA) Token(imprint []byte, nonce *big.Int) []byte {
	ca, fault := f.CA, f.Fault
	hashAlg := pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}
	if fault.SHA1Imprint {
		hashAlg = pkix.AlgorithmIdentifier{Algorithm: oidSHA1}
	}
	if fault.WrongImprint {
		imprint = bytes.Repeat([]byte{9}, 32)
	}
	if fault.WrongNonce {
		nonce = new(big.Int).Add(nonce, big.NewInt(1))
	}
	if fault.NoNonce {
		nonce = nil
	}
	genTime := TSANow
	if !fault.GenTime.IsZero() {
		genTime = fault.GenTime
	}
	type tstInfo struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint messageImprint
		SerialNumber   *big.Int
		GenTime        time.Time `asn1:"generalized"`
		Accuracy       accuracy  `asn1:"optional"`
		Nonce          *big.Int  `asn1:"optional"`
	}
	content := f.marshal(tstInfo{
		Version: 1, Policy: asn1.ObjectIdentifier{1, 2, 3, 4}, SerialNumber: big.NewInt(4242),
		MessageImprint: messageImprint{HashAlgorithm: hashAlg, HashedMessage: imprint},
		GenTime:        genTime, Accuracy: accuracy{Seconds: 1}, Nonce: nonce,
	})

	digest := sha256.Sum256(content)
	if fault.WrongDigest {
		digest = sha256.Sum256([]byte("other"))
	}
	var attrs [][]byte
	if !fault.NoContentType {
		attrs = append(attrs, f.marshal(attribute{oidContentType, asn1.RawValue{FullBytes: f.setOf(f.marshal(oidTSTInfo))}}))
	}
	attrs = append(attrs, f.marshal(attribute{oidMessageDigest, asn1.RawValue{FullBytes: f.setOf(f.marshal(digest[:]))}}))
	signedAttrs := f.setOf(attrs...)

	signed := signedAttrs
	if fault.BadSignature {
		signed = []byte("not the attributes")
	}
	h := sha256.Sum256(signed)
	sig, err := ca.CertKey.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		f.T.Fatal(err)
	}
	sigAlg := pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}
	if _, ok := ca.CertKey.(*rsa.PrivateKey); ok {
		sigAlg = pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue}
	}
	type signerInfo struct {
		Version            int
		SID                asn1.RawValue
		DigestAlgorithm    pkix.AlgorithmIdentifier
		SignedAttrs        asn1.RawValue `asn1:"optional"`
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          []byte
	}
	implicit := bytes.Clone(signedAttrs)
	implicit[0] = 0xa0 // [0] IMPLICIT
	si := signerInfo{
		Version:         1,
		SID:             asn1.RawValue{FullBytes: f.marshal(issuerAndSerial{asn1.RawValue{FullBytes: ca.Cert.RawIssuer}, ca.Cert.SerialNumber})},
		DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256}, SignedAttrs: asn1.RawValue{FullBytes: implicit},
		SignatureAlgorithm: sigAlg, Signature: sig,
	}
	if fault.NoSignedAttrs {
		si.SignedAttrs = asn1.RawValue{}
	}
	signers := [][]byte{f.marshal(si)}
	if fault.TwoSigners {
		si.Version = 3
		signers = append(signers, f.marshal(si))
	}
	type encap struct {
		EContentType asn1.ObjectIdentifier
		EContent     asn1.RawValue
	}
	type signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo encap
		Certificates     asn1.RawValue `asn1:"optional"`
		SignerInfos      asn1.RawValue
	}
	sd := signedData{
		Version:          3,
		DigestAlgorithms: asn1.RawValue{FullBytes: f.setOf(f.marshal(pkix.AlgorithmIdentifier{Algorithm: oidSHA256}))},
		EncapContentInfo: encap{oidTSTInfo, wrap0(f.marshal(content))},
		SignerInfos:      asn1.RawValue{FullBytes: f.setOf(signers...)},
	}
	if !fault.NoCerts {
		sd.Certificates = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: ca.Cert.Raw}
	}
	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}
	return f.marshal(contentInfo{oidSignedData, wrap0(f.marshal(sd))})
}

// Response wraps a token in a granted TimeStampResp.
func (f *TSA) Response(token []byte) []byte {
	type resp struct {
		Status pkiStatusInfo
		Token  asn1.RawValue `asn1:"optional"`
	}
	return f.marshal(resp{Token: asn1.RawValue{FullBytes: token}})
}

// acceptTimestampRequest checks a request as an authority would: version 1, a SHA-256
// imprint, a nonce and certReq.
func acceptTimestampRequest(body []byte) (timeStampReq, bool) {
	var r timeStampReq
	rest, err := asn1.Unmarshal(body, &r)
	return r, err == nil && len(rest) == 0 && r.Version == 1 && r.CertReq && r.Nonce != nil &&
		r.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) && len(r.MessageImprint.HashedMessage) == 32
}

// Do implements the anchor package's Doer.
func (f *TSA) Do(req *http.Request) (*http.Response, error) {
	f.Calls++
	if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/timestamp-query" || req.URL.Host != "tsa.test" {
		return Reply(http.StatusBadRequest, nil), nil
	}
	body, _ := io.ReadAll(req.Body)
	f.Request = body
	r, ok := acceptTimestampRequest(body)
	if !ok {
		return Reply(http.StatusBadRequest, nil), nil
	}
	if f.Fault.Status != 0 {
		type refused struct{ Status pkiStatusInfo }
		return Reply(http.StatusOK, f.marshal(refused{pkiStatusInfo{f.Fault.Status}})), nil
	}
	return Reply(http.StatusOK, f.Response(f.Token(r.MessageImprint.HashedMessage, r.Nonce))), nil
}
