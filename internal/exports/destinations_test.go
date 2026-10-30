// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package exports

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/sigv4"
)

const ownHost = "pc.example.com"

func put(u string) Target { return Target{Kind: KindHTTPSPut, URL: u} }

func s3(u, bucket string) Target {
	return Target{Kind: KindS3, URL: u, Bucket: bucket, Region: "eu-west-1"}
}

// TestHR513_PrivateAndMetadataHostsRefused: a target that reaches a private
// or metadata host is refused, whichever spelling reaches it, and the rules
// read the host requests really go to: a bucket's name is part of it.
// Covers: F517
func TestHR513_PrivateAndMetadataHostsRefused(t *testing.T) {
	internal := func(tg Target) Target {
		tg.Internal = true
		return tg
	}
	cases := []struct {
		name string
		t    Target
		want error
	}{
		{"private", put("https://10.0.0.5/x"), ErrURL},
		{"loopback", put("https://127.0.0.1:8443/x"), ErrURL},
		{"ipv6 loopback", put("https://[::1]:8443/x"), ErrURL},
		{"own host", put("https://pc.example.com/x"), ErrURL},
		{"plain http", put("http://store.example.net/x"), ErrURL},
		{"userinfo", put("https://u:p@store.example.net/x"), ErrURL},
		{"query", put("https://store.example.net/x?sig=abc"), ErrURL},
		{"s3 endpoint with a path", s3("https://store.example.net/other", "bkt"), ErrURL},
		{"metadata address", internal(put("https://169.254.169.254/latest")), ErrMetadata},
		{"metadata name", internal(put("https://metadata.google.internal/")), ErrMetadata},
		{"metadata through the bucket's name", internal(s3("https://google.internal", "metadata")), ErrMetadata},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := CheckTarget(c.t, ownHost, nil); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
	for _, ok := range []Target{
		put("https://store.example.net/in"),
		s3("https://s3.eu-west-1.amazonaws.com", "evidence-bkt"),
		internal(put("https://10.0.0.5:8443/in")),
	} {
		if err := CheckTarget(ok, ownHost, nil); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
}

func TestTargetBase(t *testing.T) {
	v := s3("https://s3.example.net", "bkt")
	u, err := v.Base()
	if err != nil || u.String() != "https://bkt.s3.example.net" {
		t.Fatalf("virtual host: %v %v", u, err)
	}
	v.PathStyle = true
	u, err = v.Base()
	if err != nil || u.String() != "https://s3.example.net/bkt" {
		t.Fatalf("path style: %v %v", u, err)
	}
}

func TestTargetValid(t *testing.T) {
	prefixed := func(p string) Target {
		tg := put("https://store.example.net/in")
		tg.KeyPrefix = p
		return tg
	}
	for _, ok := range []Target{prefixed(""), prefixed("a/b.c/d_e-f"), s3("https://s.example.net", "my.bkt-1")} {
		if !ok.valid() {
			t.Errorf("refused %+v", ok)
		}
	}
	noRegion := s3("https://s.example.net", "bkt")
	noRegion.Region = ""
	stray := put("https://store.example.net/in")
	stray.Bucket = "bkt"
	for _, bad := range []Target{
		prefixed("/a"), prefixed("a/"), prefixed("a//b"), prefixed("../a"), prefixed("a/../b"), prefixed("a/./b"), prefixed(".hidden"),
		prefixed("a b"), prefixed(strings.Repeat("a", 257)),
		s3("https://s.example.net", "UPPER"), s3("https://s.example.net", "a..b"), s3("https://s.example.net", "b/k"),
		noRegion, stray,
		{Kind: "ftp", URL: "https://s.example.net"},
	} {
		if bad.valid() {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestDataClasses(t *testing.T) {
	if !validClasses(dataClasses) || !validClasses([]string{ClassProofBundles}) {
		t.Fatal("refused a valid list")
	}
	for _, bad := range [][]string{nil, {}, {"payloads"}, {ClassOrgExports, ClassOrgExports}} {
		if validClasses(bad) {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestCredentialValid(t *testing.T) {
	key := sigv4.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret/value+1"}
	if !(Credential{BearerToken: "token-1234"}).valid(KindHTTPSPut) || !(Credential{S3: key}).valid(KindS3) {
		t.Fatal("refused a valid credential")
	}
	session := key
	session.SessionToken = "short-lived"
	for name, c := range map[string]struct {
		c    Credential
		kind string
	}{
		"empty token":      {Credential{}, KindHTTPSPut},
		"header injection": {Credential{BearerToken: "token-1234\r\nX-Evil: 1"}, KindHTTPSPut},
		"key for a PUT":    {Credential{BearerToken: "token-1234", S3: key}, KindHTTPSPut},
		"token for s3":     {Credential{BearerToken: "token-1234", S3: key}, KindS3},
		"no secret":        {Credential{S3: sigv4.Credentials{AccessKeyID: "AKIAEXAMPLE"}}, KindS3},
		"key id injection": {Credential{S3: sigv4.Credentials{AccessKeyID: "AK/IA, x", SecretAccessKey: "secret-value"}}, KindS3},
		"session token":    {Credential{S3: session}, KindS3},
	} {
		if c.c.valid(c.kind) {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestCredentialNeverRenders: neither secret reaches fmt, encoding/json or
// slog, alone or inside a NewDestination.
func TestCredentialNeverRenders(t *testing.T) {
	c := Credential{BearerToken: "TOKENVALUEX", S3: sigv4.Credentials{AccessKeyID: "AKIDX", SecretAccessKey: "SECRETVALUEX"}}
	in := NewDestination{Name: "x", Credential: c}
	var outs []string
	for _, f := range []string{"%v", "%s", "%+v", "%#v"} {
		outs = append(outs, fmt.Sprintf(f, c), fmt.Sprintf(f, in), fmt.Sprintf(f, &c))
	}
	for _, v := range []any{c, in, &c} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, string(b))
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "c", c, "in", in)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "c", c)
	outs = append(outs, buf.String())
	for _, o := range outs {
		if strings.Contains(o, "TOKENVALUEX") || strings.Contains(o, "SECRETVALUEX") {
			t.Fatalf("rendered: %s", o)
		}
	}
}
