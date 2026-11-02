// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package outofprocess_test

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/katocxl/pantherclaw/internal/contentsignals/adapters/outofprocess"
	"github.com/katocxl/pantherclaw/internal/contentsignals/domain"
	"github.com/katocxl/pantherclaw/internal/contentsignals/ports"
)

func server(t *testing.T, status int, body string) *outofprocess.Classifier {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(s.Close)
	c, err := outofprocess.New(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func call(c *outofprocess.Classifier) ([]domain.Finding, error) {
	return c.Classify(context.Background(), ports.Input{Surface: ports.SurfaceResult, Location: "result", Content: []byte("text")})
}

// TestHR649_ClassifierAddress: only an IP literal on this machine or a
// private network; a name or a public address is refused.
//
// Covers: F940
func TestHR649_ClassifierAddress(t *testing.T) {
	for raw, ok := range map[string]bool{
		"http://127.0.0.1:9000/classify": true, "http://[::1]:9000/": true, "https://10.1.2.3/x": true,
		"http://classifier.example.com/": false, "https://api.vendor.example/v1": false, "http://8.8.8.8/": false,
		"ftp://127.0.0.1/": false, "http://user:pw@127.0.0.1/": false, "": false,
	} {
		if err := outofprocess.CheckURL(raw); (err == nil) != ok {
			t.Errorf("%q: %v", raw, err)
		}
	}
}

// TestClassify_AFlagIsAClassifierFlag: whatever the service says is a
// classifier_flag, with its location.
//
// Covers: F940
func TestClassify_AFlagIsAClassifierFlag(t *testing.T) {
	got, err := call(server(t, 200, `{"flags":[{"location":"result/a"},{}]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []domain.Finding{{Kind: domain.KindClassifierFlag, Location: "result/a"}, {Kind: domain.KindClassifierFlag, Location: "result"}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("%+v", got)
	}
	if got, err := call(server(t, 200, `{"flags":[]}`)); err != nil || len(got) != 0 {
		t.Fatalf("%+v %v", got, err)
	}
}

// TestClassify_RequestHoldsTheBody: the body goes as sent, once.
//
// Covers: F940
func TestClassify_RequestHoldsTheBody(t *testing.T) {
	var got struct {
		Surface  string `json:"surface"`
		Location string `json:"location"`
		Content  string `json:"content_base64"`
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.UnmarshalRead(r.Body, &got); err != nil {
			t.Error(err)
		}
		_, _ = io.WriteString(w, `{"flags":[]}`)
	}))
	defer s.Close()
	c, err := outofprocess.New(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := call(c); err != nil {
		t.Fatal(err)
	}
	if raw, _ := base64.StdEncoding.DecodeString(got.Content); string(raw) != "text" || got.Surface != "result" {
		t.Fatalf("%+v", got)
	}
}

// TestHR650_AnythingElseIsAnError: an error is what the scan makes a
// scan_incomplete.
//
// Covers: F940
func TestHR650_AnythingElseIsAnError(t *testing.T) {
	for name, c := range map[string]*outofprocess.Classifier{
		"status":   server(t, 500, `{"flags":[]}`),
		"redirect": server(t, 302, ``),
		"not json": server(t, 200, `ok`),
		"no flags": server(t, 200, `{}`),
		"extra":    server(t, 200, `{"flags":[],"safe":true}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := call(c); err == nil {
				t.Fatal("no error")
			}
		})
	}
	s := httptest.NewServer(http.NotFoundHandler())
	c, err := outofprocess.New(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := call(c); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("closed: %v", err)
	}
}
