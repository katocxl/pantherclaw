// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	awssim "github.com/katocxl/pantherclaw/internal/sim/aws"
	pcawsssm "github.com/katocxl/pantherclaw/packages/pc-aws-ssm"
)

// TestT348_AnSSMCommandRunsInASessionOfItsInstanceAndDocument: the
// dispatch of aws.ssm.send_command and aws.ssm.send_powershell_command is
// signed by a session narrowed to ssm:SendCommand on exactly the target
// instance's ARN and the operation's document ARN (HR-525, FQ34-4), which
// the strict simulator, like IAM, needs both of (D1203); the session does
// not cover another instance.
func TestT348_AnSSMCommandRunsInASessionOfItsInstanceAndDocument(t *testing.T) {
	const secret = "simulated/base+secret0123456789"
	sim := awssim.New(secret, "", []string{"*"}, awssim.Faults{}, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	plain, err := credentials.AWSSigV4{
		V: 1, AccessKeyID: awssim.BaseKeyID, SecretAccessKey: []byte(secret), RoleARN: awssim.RoleARN,
		STSURL: srv.URL, STSRegion: awssim.Region, Region: awssim.Region, Service: "ssm",
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{
		broker: &plainOpener{plain: plain}, allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		tokenClients: map[string]clientEntry{}, log: pclog.Discard(),
	}
	conn := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c", BaseUrl: srv.URL}, Credential: &pb.SealedCredential{
		Kind: credentials.KindAWSSigV4, AllowedHosts: []string{u.Host}, Header: "Authorization", Scheme: "AWS4-HMAC-SHA256",
	}}
	p, err := manifest.Decode(pcawsssm.Package)
	if err != nil {
		t.Fatal(err)
	}
	send := func(t *testing.T, op, doc string, instances ...string) int {
		t.Helper()
		def, ok := p.Definition(op)
		if !ok {
			t.Fatalf("no %s", op)
		}
		body, _ := json.Marshal(map[string]any{
			"DocumentName": doc, "InstanceIds": instances, "Parameters": map[string][]string{"commands": {"uptime"}},
		})
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", "AmazonSSM.SendCommand")
		_, release, _, err := e.credential(context.Background(), conn, def, actionir.Target{Type: "aws_ec2_instance", ID: awssim.Instance}, req, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}
	for op, doc := range map[string]string{"aws.ssm.send_command": "AWS-RunShellScript", "aws.ssm.send_powershell_command": "AWS-RunPowerShellScript"} {
		if code := send(t, op, doc, awssim.Instance); code != http.StatusOK {
			t.Fatalf("%s: HTTP %d, calls %+v", op, code, sim.Calls())
		}
		calls := sim.Calls()
		if last := calls[len(calls)-1]; !last.Allowed || last.Key != "session" || !slices.Equal(last.Policy, []string{"ssm:SendCommand"}) {
			t.Fatalf("%s: call %+v", op, last)
		}
	}
	if n := len(sim.Commands()); n != 2 {
		t.Fatalf("commands run %d", n)
	}
	// The session names one instance and one document: a second instance,
	// or the other document, is outside it.
	if code := send(t, "aws.ssm.send_command", "AWS-RunShellScript", awssim.Instance, awssim.SecondInstance); code == http.StatusOK {
		t.Fatal("a second instance ran in the session")
	}
	if code := send(t, "aws.ssm.send_command", "AWS-RunPowerShellScript", awssim.Instance); code == http.StatusOK {
		t.Fatal("another document ran in the session")
	}
	if n := len(sim.Commands()); n != 2 {
		t.Fatalf("refused sessions ran %d commands", n-2)
	}
}
