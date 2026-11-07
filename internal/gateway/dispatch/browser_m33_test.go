// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"encoding/json/jsontext"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// TestHR747_TheSecretFieldPreCheck: a pc.browser browser.form.submit whose
// secret_fields is true, missing or unreadable is refused and reported
// (browser_secret_field); false, another operation or another package goes
// on to the decision.
func TestHR747_TheSecretFieldPreCheck(t *testing.T) {
	conn := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "01920000-0000-7000-8000-0000000000c2", Kind: "local"}}
	run := "01920000-0000-7000-8000-0000000000d1"
	for name, tc := range map[string]struct {
		pkg, op, params string
		refused         bool
	}{
		"secret":        {browserPackage, browserSubmit, `{"secret_fields":true,"url":"https://a.example/"}`, true},
		"missing":       {browserPackage, browserSubmit, `{"url":"https://a.example/"}`, true},
		"unreadable":    {browserPackage, browserSubmit, `{"secret_fields":"no"}`, true},
		"null":          {browserPackage, browserSubmit, `{"secret_fields":null}`, true},
		"not json":      {browserPackage, browserSubmit, `nope`, true},
		"not secret":    {browserPackage, browserSubmit, `{"secret_fields":false}`, false},
		"navigate":      {browserPackage, "browser.navigate", `{"secret_fields":true}`, false},
		"other package": {"pc.mock-payments", browserSubmit, `{"secret_fields":true}`, false},
	} {
		var reported []string
		e := &Engine{log: pclog.Discard(), localRefusals: func(_ context.Context, c, code, op, r string, _ RefusalDetail) error {
			reported = append(reported, c+" "+code+" "+op+" "+r)
			return nil
		}}
		a := actionir.ActionIR{
			Operation: tc.op, RunID: run, Params: jsontext.Value(tc.params),
			Definition: actionir.Definition{Package: tc.pkg},
		}
		got := e.browserSecretField(context.Background(), conn, a)
		if got != tc.refused {
			t.Errorf("%s: refused %v", name, got)
		}
		want := 0
		if tc.refused {
			want = 1
		}
		if len(reported) != want || (want == 1 && reported[0] != conn.GetId()+" browser_secret_field "+tc.op+" "+run) {
			t.Errorf("%s: reported %v", name, reported)
		}
	}
}
