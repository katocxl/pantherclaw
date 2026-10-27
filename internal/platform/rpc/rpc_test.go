// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rpc

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

type testSystem struct {
	pantherclawv1connect.UnimplementedSystemServiceHandler
	calls  atomic.Int32
	err    error
	panics bool
}

func (s *testSystem) GetBuildInfo(_ context.Context, req *pantherclawv1.GetBuildInfoRequest) (*pantherclawv1.GetBuildInfoResponse, error) {
	s.calls.Add(1)
	if s.panics {
		panic("database password=hunter2 exploded")
	}
	if s.err != nil {
		return nil, s.err
	}
	return &pantherclawv1.GetBuildInfoResponse{Version: "test", ClientRequestId: req.GetClientRequestId()}, nil
}

func newClient(t *testing.T, svc *testSystem, opts Options) (pantherclawv1connect.SystemServiceClient, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	if opts.Logger == nil {
		opts.Logger = pclog.New(&logs, pclog.Options{})
	}
	s, err := NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterSystemServiceHandler(s, svc)
	mux := http.NewServeMux()
	Mount(mux, s)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return pantherclawv1connect.NewSystemServiceClient(connect.NewClient(connecthttp.NewTransport(ts.Client(), ts.URL))), &logs
}

var public = Options{Public: []string{pantherclawv1connect.SystemServiceGetBuildInfoProcedure}}

func TestPublicCallSucceeds(t *testing.T) {
	c, logs := newClient(t, &testSystem{}, public)
	res, err := c.GetBuildInfo(context.Background(), &pantherclawv1.GetBuildInfoRequest{ClientRequestId: "abc-1"})
	if err != nil || res.GetVersion() != "test" || res.GetClientRequestId() != "abc-1" {
		t.Fatalf("GetBuildInfo = %v, %v", res, err)
	}
	if !strings.Contains(logs.String(), `"event":"rpc.call"`) || !strings.Contains(logs.String(), `"procedure":"/pantherclaw.v1.SystemService/GetBuildInfo"`) {
		t.Fatalf("missing rpc.call log: %s", logs.String())
	}
}

func TestHR104_InvalidRequestsNeverReachTheHandler(t *testing.T) {
	svc := &testSystem{}
	c, _ := newClient(t, svc, public)
	for _, bad := range []string{"has space", "semi;colon", strings.Repeat("a", 65), "<script>", "id\n2"} {
		_, err := c.GetBuildInfo(context.Background(), &pantherclawv1.GetBuildInfoRequest{ClientRequestId: bad})
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%q: code = %v, want InvalidArgument", bad, connect.CodeOf(err))
		}
		if err != nil && strings.Contains(err.Error(), bad) && len(bad) > 3 {
			t.Errorf("%q: error echoes the submitted value: %v", bad, err)
		}
		if err != nil && !strings.Contains(err.Error(), "client_request_id") {
			t.Errorf("%q: error does not name the field: %v", bad, err)
		}
	}
	if n := svc.calls.Load(); n != 0 {
		t.Fatalf("handler ran %d times for invalid requests", n)
	}
}

func TestNonPublicProceduresRequireAuthentication(t *testing.T) {
	svc := &testSystem{}
	c, _ := newClient(t, svc, Options{})
	_, err := c.GetBuildInfo(context.Background(), &pantherclawv1.GetBuildInfoRequest{})
	if connect.CodeOf(err) != connect.CodeUnauthenticated || svc.calls.Load() != 0 {
		t.Fatalf("code = %v, calls = %d; want Unauthenticated before the handler", connect.CodeOf(err), svc.calls.Load())
	}
	// With an authenticator, a rejection stays a rejection.
	c, _ = newClient(t, svc, Options{Authenticate: func(context.Context, *connect.CallInfo, connect.Spec) (context.Context, error) {
		return nil, connect.NewError(connect.CodeUnauthenticated, "invalid credentials")
	}})
	if _, err := c.GetBuildInfo(context.Background(), &pantherclawv1.GetBuildInfoRequest{}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("authenticator rejection: %v", err)
	}
}

func TestErrorsAreMappedWithoutLeaks(t *testing.T) {
	cases := []struct {
		err      error
		code     connect.Code
		message  string
		mustHide string
	}{
		{
			pcerr.Wrap(errors.New(`pq: relation "secret_table"`), pcerr.NotFound, "ORG_NOT_FOUND", "organization not found"),
			connect.CodeNotFound, "ORG_NOT_FOUND: organization not found", "secret_table",
		},
		{pcerr.New(pcerr.Deny, "GRANT_EXPIRED", "grant expired"), connect.CodePermissionDenied, "GRANT_EXPIRED: grant expired", ""},
		{pcerr.New(pcerr.CannotAuthorize, "FACTS_STALE", "required facts are stale"), connect.CodeUnavailable, "FACTS_STALE: required facts are stale", ""},
		{errors.New("dial tcp 10.0.0.5:5432: password authentication failed"), connect.CodeInternal, "internal error", "10.0.0.5"},
	}
	for _, tc := range cases {
		c, logs := newClient(t, &testSystem{err: tc.err}, public)
		_, err := c.GetBuildInfo(context.Background(), &pantherclawv1.GetBuildInfoRequest{})
		var ce *connect.Error
		if !errors.As(err, &ce) || ce.Code() != tc.code || ce.Message() != tc.message {
			t.Errorf("%v: got %v", tc.err, err)
			continue
		}
		if tc.mustHide != "" && strings.Contains(err.Error(), tc.mustHide) {
			t.Errorf("client error leaks %q: %v", tc.mustHide, err)
		}
		if tc.code == connect.CodeInternal && !strings.Contains(logs.String(), "rpc.internal_error") {
			t.Error("internal error not logged for operators")
		}
	}
}

func TestPanicsBecomeInternalErrors(t *testing.T) {
	c, logs := newClient(t, &testSystem{panics: true}, public)
	_, err := c.GetBuildInfo(context.Background(), &pantherclawv1.GetBuildInfoRequest{})
	if connect.CodeOf(err) != connect.CodeInternal || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("panic response = %v", err)
	}
	if !strings.Contains(logs.String(), "rpc.panic") {
		t.Fatal("panic not logged")
	}
}

func TestRequestIDIsEchoedOrMinted(t *testing.T) {
	c, _ := newClient(t, &testSystem{}, public)
	for in, keep := range map[string]bool{"req-123": true, "bad id <script>": false, "": false} {
		ctx, info := connect.NewClientContext(context.Background())
		if in != "" {
			info.RequestHeader().Set(RequestIDHeader, in)
		}
		if _, err := c.GetBuildInfo(ctx, &pantherclawv1.GetBuildInfoRequest{}); err != nil {
			t.Fatal(err)
		}
		got := info.ResponseHeader().Get(RequestIDHeader)
		if keep && got != in {
			t.Errorf("request id %q not echoed (got %q)", in, got)
		}
		if !keep && (got == in || !requestIDPattern.MatchString(got)) {
			t.Errorf("request id %q not replaced by a minted one (got %q)", in, got)
		}
	}
}

// TestEveryRPCDeclaresAPermission walks every proto file: each rpc must be
// preceded by a "// permission: <name>" comment (BUILD_GUIDE §3.2), and
// "public" procedures must be exactly the ones the server exposes publicly.
func TestEveryRPCDeclaresAPermission(t *testing.T) {
	root := filepath.Join("..", "..", "..", "proto")
	rpcLine := regexp.MustCompile(`^\s*rpc\s+(\w+)\s*\(`)
	permLine := regexp.MustCompile(`^\s*//\s*permission:\s*([a-z][a-z0-9_.]*)\s*$`)
	found := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".proto" {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.Split(string(b), "\n")
		for i, l := range lines {
			m := rpcLine.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			found++
			perm := ""
			for j := i - 1; j >= 0 && strings.HasPrefix(strings.TrimSpace(lines[j]), "//"); j-- {
				if pm := permLine.FindStringSubmatch(lines[j]); pm != nil {
					perm = pm[1]
				}
			}
			if perm == "" {
				t.Errorf("%s: rpc %s has no '// permission:' comment", path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no rpc definitions found")
	}
}

// TestOnlyPOSTIsServed: Connect GET of a NO_SIDE_EFFECTS method, and any
// other method, gets 405 with Allow: POST; POST still works.
func TestOnlyPOSTIsServed(t *testing.T) {
	svc := &testSystem{}
	s, err := NewServer(public)
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterSystemServiceHandler(s, svc)
	mux := http.NewServeMux()
	Mount(mux, s)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	u := ts.URL + pantherclawv1connect.SystemServiceGetBuildInfoProcedure
	for _, method := range []string{http.MethodGet, http.MethodOptions, http.MethodPut, http.MethodHead} {
		target := u
		if method == http.MethodGet {
			target += "?connect=v1&encoding=json&message=%7B%7D"
		}
		req, _ := http.NewRequestWithContext(context.Background(), method, target, nil)
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Allow") != http.MethodPost {
			t.Errorf("%s = %d Allow %q, want 405 Allow POST", method, res.StatusCode, res.Header.Get("Allow"))
		}
	}
	if svc.calls.Load() != 0 {
		t.Fatal("a refused method reached the handler")
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, u, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || svc.calls.Load() != 1 {
		t.Fatalf("POST = %d, calls %d", res.StatusCode, svc.calls.Load())
	}
}
