// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package selfmcp

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordingTransport struct {
	paths   []string
	clients []string
}

func (t *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.paths = append(t.paths, r.URL.Path)
	t.clients = append(t.clients, r.Header.Get(ClientHeader))
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
}

// TestHR663_TheTransportNamesTheClient: every call `pclaw mcp self` sends
// carries Pantherclaw-Client: mcp-self, set on a copy, so the request its
// caller built is left as it was.
// Covers: F947
func TestHR663_TheTransportNamesTheClient(t *testing.T) {
	base := &recordingTransport{}
	tr := AllowList{Base: base}
	for _, p := range Procedures() {
		r, err := http.NewRequest(http.MethodPost, "https://pc.example.test"+p, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		res, err := tr.RoundTrip(r)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		_ = res.Body.Close()
		if r.Header.Get(ClientHeader) != "" {
			t.Errorf("%s: the caller's request was changed", p)
		}
	}
	if len(base.clients) != len(Procedures()) {
		t.Fatalf("sent %v", base.paths)
	}
	for i, c := range base.clients {
		if c != "mcp-self" || ClientHeader != "Pantherclaw-Client" {
			t.Errorf("%s: %s: %q", base.paths[i], ClientHeader, c)
		}
	}
}

// TestHR656_TransportSendsOnlyTheAllowList: a request off the list never
// leaves the process, whatever a bug above it asks for.
// Covers: F947
func TestHR656_TransportSendsOnlyTheAllowList(t *testing.T) {
	base := &recordingTransport{}
	tr := AllowList{Base: base}
	send := func(method, path string) error {
		r, err := http.NewRequest(method, "https://pc.example.test"+path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		res, err := tr.RoundTrip(r)
		if err == nil {
			_ = res.Body.Close()
		}
		return err
	}
	for _, p := range Procedures() {
		if err := send(http.MethodPost, p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, p := range []string{
		pantherclawv1connect.SearchServiceSaveQueryProcedure,
		pantherclawv1connect.SearchServiceDeleteSavedQueryProcedure,
		pantherclawv1connect.ModelServiceDraftQueryProcedure,
		pantherclawv1connect.EvidenceServiceExportBundleProcedure,
		pantherclawv1connect.GrantServiceRevokeGrantProcedure,
	} {
		if err := send(http.MethodPost, p); !errors.Is(err, errNotAllowed) {
			t.Errorf("%s: %v", p, err)
		}
	}
	if err := send(http.MethodGet, Procedures()[0]); !errors.Is(err, errNotAllowed) {
		t.Errorf("a GET: %v", err)
	}
	// The path is compared whole: a procedure under another path, or with
	// more after it, is off the list.
	for _, p := range []string{
		"/anything" + Procedures()[2], Procedures()[2] + "/", Procedures()[2] + "x", "/" + Procedures()[2],
	} {
		if err := send(http.MethodPost, p); !errors.Is(err, errNotAllowed) {
			t.Errorf("%s: %v", p, err)
		}
	}
	if len(base.paths) != len(Procedures()) {
		t.Errorf("sent %v", base.paths)
	}
}
