// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build sandbox

package connectors_test

import (
	"context"
	"encoding/json/jsontext"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/connectors"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker/dockertest"
)

// configuration is a gateway configuration a test changes.
type configuration struct {
	mu  sync.Mutex
	cfg *control.Config
}

func (c *configuration) Current() *control.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg
}

func (c *configuration) set(conns ...*pb.GatewayConnection) {
	cfg := &control.Config{ByID: map[string]*control.Connection{}, ByName: map[string]*control.Connection{}}
	for _, gc := range conns {
		cfg.ByID[gc.GetId()] = &control.Connection{GatewayConnection: gc}
		cfg.ByName[gc.GetName()] = cfg.ByID[gc.GetId()]
	}
	c.mu.Lock()
	c.cfg = cfg
	c.mu.Unlock()
}

// TestHR216_AConnectorRunsHardenedOverStdioWithoutRouteOrCredential: the
// supervisor runs a connector connection's image (here the MCP simulator
// over stdio) as the connector uid on an internal network of its own,
// hardened, with its credential placeholders set to the placeholder and
// nothing else of the host's; the gateway's MCP client calls its tools over
// stdio; a new revision replaces it; and a connection no longer configured
// is stopped and removed with its network (HR-084, HR-085, HR-216).
func TestHR216_AConnectorRunsHardenedOverStdioWithoutRouteOrCredential(t *testing.T) {
	c, e := dockertest.Client(t)
	image := dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/cmd/pantherclaw-sim", "internal/gateway/connectors/testdata/sim.Dockerfile")
	id := ids.NewV7().String()
	conn := func(rev int32) *pb.GatewayConnection {
		return &pb.GatewayConnection{
			Id: id, Name: "connector", Kind: connectors.Kind, State: "ACTIVE", Revision: rev,
			Connector: &pb.ConnectorSpec{
				Image: image, Command: []string{"/pantherclaw-sim", "mcp", "--stdio"}, Environment: map[string]string{"LOG_LEVEL": "info"},
				CredentialPlaceholders: []string{"GITHUB_TOKEN"}, Limits: &pb.ConnectorLimits{MemoryMib: 128, MilliCpus: 500, Pids: 64},
			},
		}
	}
	conf := &configuration{}
	conf.set(conn(1))
	sup, err := connectors.New(t.Context(), c, conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		conf.set()
		sup.Sync(ctx)
		_ = c.RemoveLabelled(ctx, id)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	sup.Sync(ctx)
	client, err := sup.Client(id)
	if err != nil {
		t.Fatal(err)
	}
	if tools, err := client.ListTools(ctx, nil); err != nil || len(tools) == 0 {
		t.Fatalf("tools/list: %d tools, %v", len(tools), err)
	}
	r, err := client.Call(ctx, "create_refund", jsontext.Value(`{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`), nil, nil)
	if err != nil || r.IsError || r.Error != nil {
		t.Fatalf("tools/call: %+v %v", r, err)
	}

	name := "pc-conn-" + strings.ReplaceAll(id, "-", "")[16:]
	info, err := c.InspectContainer(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if info.Config.User != connectors.User || info.Runtime() != e.Runtime() || len(info.HostConfig.Mounts) != 0 {
		t.Fatalf("container %+v", info.Config)
	}
	net, err := c.InspectNetwork(ctx, "pc-cnet-"+strings.ReplaceAll(id, "-", "")[16:])
	if err != nil || !net.Internal {
		t.Fatalf("network %+v %v", net, err)
	}
	env := envOf(t, c, name)
	if !slices.Contains(env, "GITHUB_TOKEN="+connectors.Placeholder) || !slices.Contains(env, "LOG_LEVEL=info") {
		t.Fatalf("environment %q", env)
	}

	conf.set(conn(2))
	sup.Sync(ctx)
	again, err := sup.Client(id)
	if err != nil || again == client {
		t.Fatalf("a new revision kept the old connector: %v", err)
	}
	if _, err := again.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}

	conf.set()
	sup.Sync(ctx)
	if _, err := sup.Client(id); err == nil {
		t.Fatal("a connector no longer configured still runs")
	}
	if _, err := c.InspectContainer(ctx, name); err == nil {
		t.Fatal("the stopped connector's container was not removed")
	}
}

// envOf is a container's environment as the engine reports it, without the
// image's own.
func envOf(t *testing.T, c *docker.Client, name string) []string {
	t.Helper()
	info, err := c.InspectContainer(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, e := range info.Config.Env {
		if !strings.HasPrefix(e, "PATH=") && !strings.HasPrefix(e, "SSL_CERT_FILE=") {
			env = append(env, e)
		}
	}
	return env
}
