// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package docker

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
)

// Bridge driver options for isolated gateway mode (Docker ≥ 28): the bridge
// gets no address on the network, so a container on it has no route to the
// host (HR-122).
const (
	optGatewayModeV4 = "com.docker.network.bridge.gateway_mode_ipv4"
	optGatewayModeV6 = "com.docker.network.bridge.gateway_mode_ipv6"
	gatewayIsolated  = "isolated"
)

// ErrIsolation reports a network or container the engine did not create as
// asked; it was removed again (HR-218).
var ErrIsolation = errors.New("docker: isolation self-check failed")

// Network is a bridge network the sandbox creates. IPv6 is always off.
type Network struct {
	Name string
	// Internal networks hold a sandbox's agent, probes and edge: no route
	// out and isolated gateway mode (HR-122, HR-213). Only the edge's
	// uplink to the gateway is not internal.
	Internal bool
	Labels   map[string]string
}

func (n Network) args() ([]string, error) {
	if err := checkName(n.Name); err != nil {
		return nil, err
	}
	labels, err := labelArgs(n.Labels)
	if err != nil {
		return nil, err
	}
	args := []string{"network", "create", "--driver", "bridge", "--ipv6=false"}
	if n.Internal {
		args = append(args, "--internal",
			"--opt", optGatewayModeV4+"="+gatewayIsolated, "--opt", optGatewayModeV6+"="+gatewayIsolated)
	}
	args = append(args, labels...)
	return append(args, n.Name), nil
}

// NetworkInfo is what the engine reports about a network.
type NetworkInfo struct {
	Name       string            `json:"Name"`
	ID         string            `json:"Id"`
	Driver     string            `json:"Driver"`
	Internal   bool              `json:"Internal"`
	EnableIPv6 bool              `json:"EnableIPv6"`
	Options    map[string]string `json:"Options"`
	IPAM       struct {
		Config []struct {
			Subnet  string `json:"Subnet"`
			Gateway string `json:"Gateway"`
		} `json:"Config"`
	} `json:"IPAM"`
}

// Subnet is the network's first IPv4 subnet, "" when none.
func (i NetworkInfo) Subnet() string {
	if len(i.IPAM.Config) == 0 {
		return ""
	}
	return i.IPAM.Config[0].Subnet
}

// CreateNetwork creates n and checks what the engine made of it (HR-218);
// a network that fails the check is removed again.
func (c *Client) CreateNetwork(ctx context.Context, n Network) (NetworkInfo, error) {
	args, err := n.args()
	if err != nil {
		return NetworkInfo{}, err
	}
	if _, err := c.r.Run(ctx, args...); err != nil {
		return NetworkInfo{}, err
	}
	info, err := c.InspectNetwork(ctx, n.Name)
	if err == nil {
		err = VerifyNetwork(n, info)
	}
	if err != nil {
		return NetworkInfo{}, errors.Join(err, c.RemoveNetwork(context.WithoutCancel(ctx), n.Name))
	}
	return info, nil
}

// InspectNetwork reads a network.
func (c *Client) InspectNetwork(ctx context.Context, name string) (NetworkInfo, error) {
	if err := checkName(name); err != nil {
		return NetworkInfo{}, err
	}
	out, err := c.r.Run(ctx, "network", "inspect", "--format", "{{json .}}", name)
	if err != nil {
		return NetworkInfo{}, err
	}
	var info NetworkInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return NetworkInfo{}, fmt.Errorf("docker: unreadable network %s: %w", name, err)
	}
	return info, nil
}

// RemoveNetwork removes a network the sandbox created.
func (c *Client) RemoveNetwork(ctx context.Context, name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	_, err := c.r.Run(ctx, "network", "rm", name)
	return err
}

// VerifyNetwork compares what the engine reports with what was asked: a
// bridge, IPv6 off and, for an internal network, internal in isolated
// gateway mode for both address families (HR-122, HR-218). The edge's
// uplink must be in the default NAT mode: a routed or unprotected one
// would expose every port of the containers on it without publishing.
func VerifyNetwork(n Network, info NetworkInfo) error {
	fail := func(what string) error { return fmt.Errorf("%w: network %s: %s", ErrIsolation, n.Name, what) }
	switch {
	case info.Name != n.Name:
		return fail("another network answered")
	case info.Driver != "bridge":
		return fail("driver " + info.Driver)
	case info.EnableIPv6:
		return fail("IPv6 is on")
	case !n.Internal && (info.Internal || !natMode(info.Options[optGatewayModeV4]) || !natMode(info.Options[optGatewayModeV6])):
		return fail("the uplink is not a NAT bridge")
	case !n.Internal:
		return nil
	case !info.Internal:
		return fail("not internal")
	case info.Options[optGatewayModeV4] != gatewayIsolated || info.Options[optGatewayModeV6] != gatewayIsolated:
		return fail("gateway mode is not isolated")
	}
	return nil
}

// natMode reports a gateway mode that is the default NAT one.
func natMode(m string) bool { return m == "" || m == "nat" }
