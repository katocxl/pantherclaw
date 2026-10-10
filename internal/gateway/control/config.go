// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// RefetchEvery is how often the gateway refetches its configuration even
// without a change on the containment stream (decision 19).
const RefetchEvery = 60 * time.Second

// ErrConfig reports a configuration the gateway refuses to serve: for
// another org or gateway, or with a package that does not decode.
var ErrConfig = errors.New("control: configuration refused")

// Config is what this gateway serves (G0 M6 design decision 19).
type Config struct {
	Version int64
	// Org is the gateway's org (checked against its certificate).
	Org string
	// ByName and ByID index the connections (active and quarantined).
	ByName, ByID map[string]*Connection
}

// Connection is one connection with its package and credential.
type Connection struct {
	*pb.GatewayConnection
	// Package is the pinned package, decoded strictly; every definition
	// digest is derived here, not taken from the server.
	Package *domain.Package
	// Mapper maps calls through the package's reviewed mappings, compiled
	// once per configuration.
	Mapper *mapping.Mapper
	// Modes are the explicit route modes.
	Modes map[string]string
	// Credential is the active sealed credential, or nil.
	Credential *pb.SealedCredential
	// Captures are the active capture profiles covering the connection (G0
	// M7 design decision 10, HR-199); none when capture is off.
	Captures []*pb.GatewayCaptureProfile
}

// Mode is a route's mode: its explicit one, or the connection's default.
func (c *Connection) Mode(route string) string {
	if m, ok := c.Modes[route]; ok {
		return m
	}
	return c.GetDefaultMode()
}

// Store keeps the gateway's configuration: loaded before serving, refetched
// when the containment stream reports a new version and every
// RefetchEvery, and kept as it was when a fetch fails or is refused.
type Store struct {
	fetch        func(ctx context.Context, known int64) (*pb.GetConfigurationResponse, error)
	org, gateway string
	log          *slog.Logger
	every        time.Duration

	mu    sync.RWMutex
	cur   *Config
	ready chan struct{}
	once  sync.Once
	wake  chan struct{}
}

// NewStore returns the configuration store of an enrolled gateway.
func NewStore(c *Client, log *slog.Logger) *Store {
	id := c.Identity()
	return newStore(func(ctx context.Context, known int64) (*pb.GetConfigurationResponse, error) {
		return c.Gateway.GetConfiguration(ctx, &pb.GetConfigurationRequest{KnownVersion: known})
	}, id.Org.String(), id.Gateway.String(), log)
}

func newStore(fetch func(context.Context, int64) (*pb.GetConfigurationResponse, error), org, gateway string, log *slog.Logger) *Store {
	if log == nil {
		log = pclog.Discard()
	}
	return &Store{fetch: fetch, org: org, gateway: gateway, log: log, every: RefetchEvery, ready: make(chan struct{}), wake: make(chan struct{}, 1)}
}

// Current returns the configuration, or nil before the first load.
func (s *Store) Current() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// Ready is closed once a configuration is loaded.
func (s *Store) Ready() <-chan struct{} { return s.ready }

// Changed tells the store the server's configuration version; a different
// one triggers a refetch (the containment stream calls it).
func (s *Store) Changed(version int64) {
	if c := s.Current(); c != nil && c.Version == version {
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run loads the configuration and keeps it current until ctx ends. Before
// the first load it retries every second; after, a failed fetch keeps the
// previous configuration.
func (s *Store) Run(ctx context.Context) error {
	for {
		wait := s.every
		if err := s.load(ctx); err != nil {
			select {
			case <-ctx.Done():
				return nil // shutdown, not a fetch failure
			default:
			}
			s.log.WarnContext(ctx, "gateway.configuration_fetch_failed", pclog.Err(err))
			if s.Current() == nil {
				wait = time.Second
			}
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-s.wake:
			t.Stop()
		case <-t.C:
		}
	}
}

func (s *Store) load(ctx context.Context) error {
	var known int64
	if c := s.Current(); c != nil {
		known = c.Version
	}
	res, err := s.fetch(ctx, known)
	if err != nil {
		return err
	}
	if res.GetUnchanged() {
		if known == 0 {
			return fmt.Errorf("%w: unchanged before any configuration", ErrConfig)
		}
		return nil
	}
	cfg, err := s.build(res)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cur = cfg
	s.mu.Unlock()
	s.once.Do(func() { close(s.ready) })
	s.log.InfoContext(ctx, "gateway.configuration_loaded", slog.Int64("version", cfg.Version), slog.Int("connections", len(cfg.ByID)))
	return nil
}

// build checks and indexes a configuration. It is refused as a whole when
// it names another org or gateway, a package does not decode, or a
// connection's package is missing.
func (s *Store) build(res *pb.GetConfigurationResponse) (*Config, error) {
	if res.GetOrgId() != s.org || res.GetGatewayId() != s.gateway {
		return nil, fmt.Errorf("%w: it is for another org or gateway", ErrConfig)
	}
	type compiled struct {
		pkg    *domain.Package
		mapper *mapping.Mapper
	}
	pkgs := map[string]compiled{}
	for _, p := range res.GetPackages() {
		d, err := manifest.Decode(p.GetRaw())
		if err != nil || d.Name != p.GetName() || d.Version != p.GetVersion() {
			return nil, fmt.Errorf("%w: package %s@%s does not decode", ErrConfig, p.GetName(), p.GetVersion())
		}
		m, err := mapping.New(d, celenv.DefaultLimits)
		if err != nil {
			return nil, fmt.Errorf("%w: package %s@%s: %w", ErrConfig, p.GetName(), p.GetVersion(), err)
		}
		pkgs[d.Name+"@"+d.Version] = compiled{pkg: d, mapper: m}
	}
	creds := map[string]*pb.SealedCredential{}
	for _, c := range res.GetCredentials() {
		creds[c.GetConnectionId()] = c
	}
	cfg := &Config{Version: res.GetVersion(), Org: s.org, ByName: map[string]*Connection{}, ByID: map[string]*Connection{}}
	for _, gc := range res.GetConnections() {
		pkg, ok := pkgs[gc.GetPackage()+"@"+gc.GetPackageVersion()]
		if !ok {
			return nil, fmt.Errorf("%w: connection %s uses a package that was not sent", ErrConfig, gc.GetName())
		}
		c := &Connection{GatewayConnection: gc, Package: pkg.pkg, Mapper: pkg.mapper, Modes: map[string]string{}, Credential: creds[gc.GetId()]}
		for _, r := range gc.GetRoutes() {
			c.Modes[r.GetRoute()] = r.GetMode()
		}
		cfg.ByName[gc.GetName()], cfg.ByID[gc.GetId()] = c, c
	}
	for _, p := range res.GetCaptureProfiles() {
		for _, id := range p.GetConnectionIds() {
			if c, ok := cfg.ByID[id]; ok {
				c.Captures = append(c.Captures, p)
			}
		}
	}
	return cfg, nil
}
