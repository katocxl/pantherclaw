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

type recordingTransport struct{ paths []string }

func (t *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.paths = append(t.paths, r.URL.Path)
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
}

// TestHR656_TransportSendsOnlyTheAllowList: a request off the list never
// leaves the process, whatever a bug above it asks for.
// Covers: F946
func TestHR656_TransportSendsOnlyTheAllowList(t *testing.T) {
	base := &recordingTransport{}
	tr := AllowList{Base: base}
	send := func(method, path string) error {
		r, err := http.NewRequest(method, "https://pc.example.test"+path, strings.NewReader("{}")) //nolint:noctx // no call is made
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
	if len(base.paths) != len(Procedures()) {
		t.Errorf("sent %v", base.paths)
	}
}
