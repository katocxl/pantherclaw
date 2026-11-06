// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package aws

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/sigv4"
)

// session assumes the role with a session policy allowing ssm:SendCommand
// on resources.
func ssmSession(t *testing.T, srv *httptest.Server, resources ...string) sigv4.Credentials {
	t.Helper()
	res := `"` + strings.Join(resources, `","`) + `"`
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:SendCommand","Resource":[` + res + `]}]}`
	assume := url.Values{
		"Action": {"AssumeRole"}, "Version": {"2011-06-15"}, "RoleArn": {RoleARN}, "RoleSessionName": {"t"},
		"DurationSeconds": {"900"}, "Policy": {policy},
	}
	code, body := do(t, srv, signed(t, srv, "sts", sigv4.Credentials{AccessKeyID: BaseKeyID, SecretAccessKey: secret}, assume, time.Now()))
	if code != http.StatusOK {
		t.Fatalf("AssumeRole: %d %s", code, body)
	}
	field := func(name string) string {
		return regexp.MustCompile(`<` + name + `>([^<]*)</` + name + `>`).FindStringSubmatch(body)[1]
	}
	return sigv4.Credentials{AccessKeyID: field("AccessKeyId"), SecretAccessKey: field("SecretAccessKey"), SessionToken: field("SessionToken")}
}

func sendCommand(t *testing.T, srv *httptest.Server, creds sigv4.Credentials, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AmazonSSM.SendCommand")
	if err := (sigv4.Signer{Region: Region, Service: "ssm"}).Sign(req, creds, sigv4.HashPayload([]byte(body)), time.Now()); err != nil {
		t.Fatal(err)
	}
	return do(t, srv, req)
}

// TestD1203_SendCommandNeedsTheInstanceAndTheDocument: the simulator, like
// IAM, allows SendCommand only when the session policy allows it on the
// document and on every instance; a session naming only the instance or
// only the document is refused and runs nothing (G0 M34 D1203, T-348).
func TestD1203_SendCommandNeedsTheInstanceAndTheDocument(t *testing.T) {
	s := New(secret, "", []string{"*"}, Faults{}, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	inst := "arn:aws:ec2:" + Region + ":" + Account + ":instance/" + Instance
	doc := "arn:aws:ssm:" + Region + "::document/AWS-RunShellScript"
	body := `{"DocumentName":"AWS-RunShellScript","InstanceIds":["` + Instance + `"],"Parameters":{"commands":["uptime"]}}`

	if code, out := sendCommand(t, srv, ssmSession(t, srv, inst, doc), body); code != http.StatusOK || len(s.Commands()) != 1 {
		t.Fatalf("both ARNs: %d %s", code, out)
	}
	for name, res := range map[string][]string{
		"instance only": {inst},
		"document only": {doc},
		"other doc":     {inst, "arn:aws:ssm:" + Region + "::document/AWS-RunPowerShellScript"},
	} {
		code, out := sendCommand(t, srv, ssmSession(t, srv, res...), body)
		if code == http.StatusOK || !strings.Contains(out, "AccessDenied") {
			t.Errorf("%s: %d %s", name, code, out)
		}
	}
	two := `{"DocumentName":"AWS-RunShellScript","InstanceIds":["` + Instance + `","` + SecondInstance + `"],"Parameters":{"commands":["uptime"]}}`
	if code, out := sendCommand(t, srv, ssmSession(t, srv, inst, doc), two); code == http.StatusOK {
		t.Errorf("a second instance outside the session: %d %s", code, out)
	}
	if n := len(s.Commands()); n != 1 {
		t.Fatalf("refused sessions ran %d commands", n-1)
	}
	calls := s.Calls()
	if last := calls[len(calls)-1]; last.Allowed || last.Action != "SendCommand" {
		t.Fatalf("last call %+v", last)
	}
}
