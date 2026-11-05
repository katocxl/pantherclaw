// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	pcgmail "github.com/katocxl/pantherclaw/packages/pc-gmail"
)

// A subject_target dispatch goes only when the credential is a Google
// service account whose subject is the target, compared in ASCII case;
// a static credential, a service account with no subject or one acting as
// another user is refused (TARGET_NOT_CREDENTIAL_SUBJECT) before anything
// is minted (HR-721, G0 M31 D956a).
//
// Covers: HR-721
func TestHR721_ASubjectTargetIsTheServiceAccountsSubject(t *testing.T) {
	p, err := manifest.Decode(pcgmail.Package)
	if err != nil {
		t.Fatal(err)
	}
	def, _ := p.Definition("gmail.message.send")
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	sealed := func(subject string) []byte {
		t.Helper()
		plain, err := credentials.GoogleServiceAccount{
			V: 1, ClientEmail: "agent@simulated-project.iam.gserviceaccount.com", PrivateKey: pemKey,
			TokenURI: credentials.GoogleTokenURI, Subject: subject, Scopes: []string{"https://www.googleapis.com/auth/gmail.send"},
		}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return plain
	}
	target := actionir.Target{Type: "gmail_mailbox", ID: "ops@example.test"}
	check := func(kind string, plain []byte) error {
		e := &Engine{broker: &plainOpener{plain: plain}, log: pclog.Discard()}
		conn := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c"}, Credential: &pb.SealedCredential{
			Kind: kind, Header: "Authorization", Scheme: "Bearer",
		}}
		return e.checkSubjectTarget(t.Context(), conn, def, target)
	}
	if err := check(credentials.KindGoogleServiceAccount, sealed("OPS@Example.test")); err != nil {
		t.Fatalf("the subject in another case: %v", err)
	}
	for name, err := range map[string]error{
		"a static credential": check(credentials.KindStatic, []byte("not-a-service-account")),
		"no subject":          check(credentials.KindGoogleServiceAccount, sealed("")),
		"another subject":     check(credentials.KindGoogleServiceAccount, sealed("ceo@example.test")),
	} {
		if !errors.Is(err, ErrNotCredentialSubject) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
