// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package agent

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/hosting/profile"
	"github.com/katocxl/pantherclaw/internal/hosting/sni"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
)

const (
	img   = "ghcr.io/katocxl/pantherclaw-gateway@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	token = "pcg_secret_enrollment_token_value"
)

type control struct {
	pantherclawv1connect.UnimplementedHostingAgentServiceHandler
	assignments []*pb.HostingAssignment
	pulls       int
	reports     []*pb.ReportHostedGatewayRequest
	stopped     []string
	// order records calls in sequence.
	order *[]string
}

func (c *control) ListAssignments(context.Context, *pb.ListAssignmentsRequest) (*pb.ListAssignmentsResponse, error) {
	return &pb.ListAssignmentsResponse{Assignments: c.assignments}, nil
}

func (c *control) PullEnrollmentToken(context.Context, *pb.PullEnrollmentTokenRequest) (*pb.PullEnrollmentTokenResponse, error) {
	c.pulls++
	if c.pulls > 1 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, "gone")
	}
	*c.order = append(*c.order, "pull")
	return &pb.PullEnrollmentTokenResponse{Token: token, GatewayApiUrl: "https://gw-api.example.test:8443", CaSha256: "sha256:" + strings.Repeat("a", 64)}, nil
}

func (c *control) ReportHostedGateway(_ context.Context, r *pb.ReportHostedGatewayRequest) (*pb.ReportHostedGatewayResponse, error) {
	c.reports = append(c.reports, r)
	return &pb.ReportHostedGatewayResponse{}, nil
}

func (c *control) ReportStopped(_ context.Context, r *pb.ReportStoppedRequest) (*pb.ReportStoppedResponse, error) {
	c.stopped = append(c.stopped, r.GetId())
	*c.order = append(*c.order, "reported-stopped")
	return &pb.ReportStoppedResponse{}, nil
}

type engine struct {
	containers map[string]docker.Container
	running    map[string]bool
	order      *[]string
	// networks records the networks removed; networkErr fails the next removal.
	networks   []string
	networkErr error
}

func (e *engine) CreateNetwork(_ context.Context, n docker.Network) (docker.NetworkInfo, error) {
	return docker.NetworkInfo{Name: n.Name}, nil
}
func (e *engine) RemoveNetwork(_ context.Context, name string) error {
	if err := e.networkErr; err != nil {
		e.networkErr = nil
		return err
	}
	e.networks = append(e.networks, name)
	return nil
}

func (e *engine) CreateContainer(_ context.Context, c docker.Container) (docker.ContainerInfo, error) {
	e.containers[c.Name] = c
	*e.order = append(*e.order, "create")
	return docker.ContainerInfo{}, nil
}

func (e *engine) InspectContainer(_ context.Context, name string) (docker.ContainerInfo, error) {
	var i docker.ContainerInfo
	i.State.Running = e.running[name]
	if c, ok := e.containers[name]; ok && i.State.Running {
		i.NetworkSettings.Networks = map[string]jsontext.Value{c.Networks[0]: jsontext.Value(`{"IPAddress":"10.9.0.2"}`)}
	}
	return i, nil
}
func (e *engine) Start(_ context.Context, name string) error { e.running[name] = true; return nil }
func (e *engine) RemoveContainer(_ context.Context, name string) error {
	delete(e.containers, name)
	delete(e.running, name)
	*e.order = append(*e.order, "remove")
	return nil
}

// adapter makes the handler a client.
type adapter struct{ h *control }

func (a adapter) ListAssignments(ctx context.Context, r *pb.ListAssignmentsRequest) (*pb.ListAssignmentsResponse, error) {
	return a.h.ListAssignments(ctx, r)
}

func (a adapter) PullEnrollmentToken(ctx context.Context, r *pb.PullEnrollmentTokenRequest) (*pb.PullEnrollmentTokenResponse, error) {
	return a.h.PullEnrollmentToken(ctx, r)
}

func (a adapter) ReportHostedGateway(ctx context.Context, r *pb.ReportHostedGatewayRequest) (*pb.ReportHostedGatewayResponse, error) {
	return a.h.ReportHostedGateway(ctx, r)
}

func (a adapter) ReportStopped(ctx context.Context, r *pb.ReportStoppedRequest) (*pb.ReportStoppedResponse, error) {
	return a.h.ReportStopped(ctx, r)
}

func (a adapter) RenewHostCertificate(ctx context.Context, r *pb.RenewHostCertificateRequest) (*pb.RenewHostCertificateResponse, error) {
	return nil, connect.NewError(connect.CodeUnimplemented, "unimplemented")
}

func newAgent(t *testing.T) (*Agent, *control, *engine, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	// Each private directory ends 0500; open them so TempDir can clean up.
	t.Cleanup(func() {
		dirs, _ := os.ReadDir(root)
		for _, d := range dirs {
			_ = os.Chmod(filepath.Join(root, d.Name()), 0o700)
		}
	})
	var order []string
	c := &control{order: &order}
	e := &engine{containers: map[string]docker.Container{}, running: map[string]bool{}, order: &order}
	var logs bytes.Buffer
	a := &Agent{
		Control: adapter{c}, Engine: e, Private: &Private{Root: root, chown: func(string, int) error { return nil }},
		Router: &sni.Router{Domain: "example.test"}, Images: map[string]string{"1.0.0": img}, Default: "1.0.0",
		Runtime: docker.RuntimeRunc, Version: "test", Log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Health: func(context.Context, string) error { return nil },
	}
	return a, c, e, &logs
}

func assignment(state pb.HostedGatewayState) (*pb.HostingAssignment, ids.UUID) {
	id := ids.NewV7()
	return &pb.HostingAssignment{
		OrgId: ids.New[ids.Org]().String(), Id: id.String(), Slug: "acme", Hostname: "acme.gw.example.test", State: state,
		GatewayId: ids.NewV7().String(), Limits: &pb.HostedGatewayLimits{},
	}, id
}

// TestHR502_TheTokenGoesOnlyToThePrivateDirectory: the agent pulls a placed
// gateway's token once and writes it only as a 0400 file in that org's
// private directory, which its container alone mounts read-only; the
// token is in no argument, environment entry or log line, and the file is
// deleted once the gateway runs.
//
// Covers: PN-010.4
func TestHR502_TheTokenGoesOnlyToThePrivateDirectory(t *testing.T) {
	a, c, e, logs := newAgent(t)
	as, hosted := assignment(pb.HostedGatewayState_HOSTED_GATEWAY_STATE_PROVISIONED)
	c.assignments = []*pb.HostingAssignment{as}
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(a.Private.Dir(hosted), filepath.Base(profile.TokenFile))
	b, err := os.ReadFile(file)
	if err != nil || string(b) != token {
		t.Fatalf("token file: %q %v", b, err)
	}
	if fi, _ := os.Stat(file); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o400 {
		t.Errorf("token file mode %v", fi.Mode().Perm())
	}
	ct, ok := e.containers[profile.NamesOf(hosted).Container]
	if !ok {
		t.Fatal("no container")
	}
	for _, s := range slices.Concat(ct.Args, ct.Env) {
		if strings.Contains(s, token) {
			t.Fatalf("the token is in %q", s)
		}
	}
	if strings.Contains(logs.String(), token) {
		t.Fatal("the token was logged")
	}
	// A second reconcile pulls nothing more.
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.pulls != 2 { // the second answer is FailedPrecondition, ignored
		t.Fatalf("pulls %d", c.pulls)
	}
	// Running: the token leaves the tmpfs, and the route appears.
	as.State = pb.HostedGatewayState_HOSTED_GATEWAY_STATE_RUNNING
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.Private.HasToken(hosted) {
		t.Fatal("the token stayed after the gateway ran")
	}
	if len(c.reports) == 0 || !c.reports[len(c.reports)-1].GetHealthy() {
		t.Fatalf("reports %v", c.reports)
	}
	if got := a.Router.Slug("acme.gw.example.test"); got != "acme" {
		t.Fatalf("slug %q", got)
	}
}

// TestHR503_TheAgentStopsOnlyWhatTheServerRevoked: the agent removes a
// process only when the server lists it DEPROVISIONING, which it does only
// after revoking its gateway; it then removes its private directory and
// reports it stopped.
//
// Covers: PN-010.4
func TestHR503_TheAgentStopsOnlyWhatTheServerRevoked(t *testing.T) {
	a, c, e, _ := newAgent(t)
	as, hosted := assignment(pb.HostedGatewayState_HOSTED_GATEWAY_STATE_PROVISIONED)
	c.assignments = []*pb.HostingAssignment{as}
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	name := profile.NamesOf(hosted).Container
	// An assignment that disappears is not stopped by the agent on its own.
	c.assignments = nil
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.containers[name]; !ok {
		t.Fatal("a process was stopped without the server revoking it")
	}
	as.State = pb.HostedGatewayState_HOSTED_GATEWAY_STATE_DEPROVISIONING
	c.assignments = []*pb.HostingAssignment{as}
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.containers[name]; ok {
		t.Fatal("still running")
	}
	if _, err := os.Stat(a.Private.Dir(hosted)); !os.IsNotExist(err) {
		t.Fatalf("private directory left: %v", err)
	}
	if !slices.Equal(c.stopped, []string{as.GetId()}) {
		t.Fatalf("stopped %v", c.stopped)
	}
	o := *c.order
	if o[len(o)-1] != "reported-stopped" || !slices.Contains(o, "remove") {
		t.Fatalf("order %v", o)
	}
}

// TestNewPrivateRefusesANonTmpfsRoot: off Linux, or on a disk file system,
// the private root is refused (HR-502).
//
// Covers: PN-010.4
func TestNewPrivateRefusesANonTmpfsRoot(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("t.TempDir may be a tmpfs on Linux")
	}
	if _, err := NewPrivate(t.TempDir()); !errors.Is(err, ErrNotTmpfs) {
		t.Fatalf("got %v", err)
	}
}
