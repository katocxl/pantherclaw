// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package profile builds the isolation profile of one org's hosted gateway
// process on a shared host (G0 M19 D203, HR-501): one container per org,
// as a non-root uid of its own, with a read-only root, every capability
// dropped, no Docker socket, cgroup CPU, memory and pids limits and a
// network of its own. The container is described for internal/sandbox/docker,
// which renders the Docker CLI's arguments itself and checks what the
// engine made of them (the HR-216/HR-218 pattern). No connector container
// is ever made for a hosted gateway (HR-084).
package profile

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
)

// Paths inside the container.
const (
	// EnrollDir is where the host's private tmpfs directory of the org is
	// mounted read-only; TokenFile holds the single-use enrollment token
	// until the gateway enrolled (HR-502).
	EnrollDir = "/run/pantherclaw/enroll"
	TokenFile = EnrollDir + "/token"
	// ConfigFile is the gateway's configuration (no secret), in the same
	// read-only mount.
	ConfigFile = EnrollDir + "/gateway.json"
	// StateDir is the gateway's own volume: its key and certificate.
	StateDir = "/var/lib/pantherclaw-gateway"
	// Port is the agent-facing port the gateway listens on; the host's
	// SNI router forwards to it on the org's network.
	Port = 8443
)

// UID range: every hosted gateway runs as its own uid and gid, above the
// sandbox's MinID and every host account. A host refuses to start two
// processes on one uid (Host.Check).
const (
	uidBase  = 200000
	uidRange = 1 << 24
)

// Limits are a hosted gateway's cgroup limits (T-218).
type Limits struct {
	MilliCPUs int
	MemoryMiB int
	PIDs      int
}

// DefaultLimits keep one gateway under the PN-011.1 memory target with
// headroom, and its CPU and processes small.
var DefaultLimits = Limits{MilliCPUs: 500, MemoryMiB: 256, PIDs: 128}

// Ceilings bound what a plan may ask for, whatever the record says.
var Ceilings = Limits{MilliCPUs: 2000, MemoryMiB: 1024, PIDs: 512}

// ErrProfile reports a hosted gateway the profile refuses to describe.
var ErrProfile = errors.New("hosting profile: refused")

var imageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)

// Spec is what the host agent knows of one hosted gateway.
type Spec struct {
	// Hosted is the hosted gateway record's id; every name derives from it.
	Hosted ids.UUID
	// Image is the gateway image of the version to run, pinned by digest.
	Image string
	// Root is the org's private directory on the host's tmpfs (0700, the
	// agent's own); it holds ConfigFile and TokenFile and nothing else.
	Root   string
	Limits Limits
	// Runtime is docker.RuntimeRunc or docker.RuntimeRunsc.
	Runtime string
}

// Names of a hosted gateway's engine objects.
type Names struct {
	Container, Network, Volume string
}

// LabelHosted marks a hosted gateway's resources with its record's id.
const LabelHosted = "io.pantherclaw.hosted"

// NamesOf derives the engine names of a hosted gateway: "pc-hg…", the
// record id's 32 hex digits.
func NamesOf(hosted ids.UUID) Names {
	h := hex32(hosted)
	return Names{Container: "pc-hgc-" + h, Network: "pc-hgn-" + h, Volume: "pc-hgv-" + h}
}

func hex32(id ids.UUID) string {
	const digits = "0123456789abcdef"
	b := id[:]
	out := make([]byte, 0, 32)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

// UID is the uid and gid a hosted gateway runs as, derived from its record
// id: a different one for every org on a host but for a 2^-24 collision,
// which the host refuses rather than shares.
func UID(hosted ids.UUID) int {
	sum := sha256.Sum256(hosted[:])
	return uidBase + int(binary.BigEndian.Uint32(sum[:4])%uidRange)
}

// clamp keeps limits positive and below the ceilings.
func clamp(l Limits) Limits {
	pick := func(v, def, ceil int) int {
		if v <= 0 {
			return def
		}
		return min(v, ceil)
	}
	return Limits{
		MilliCPUs: pick(l.MilliCPUs, DefaultLimits.MilliCPUs, Ceilings.MilliCPUs),
		MemoryMiB: pick(l.MemoryMiB, DefaultLimits.MemoryMiB, Ceilings.MemoryMiB),
		PIDs:      pick(l.PIDs, DefaultLimits.PIDs, Ceilings.PIDs),
	}
}

// Network is the org's own bridge network: not internal, since the gateway
// calls the server and its targets; no other org's container joins it.
func (s Spec) Network() docker.Network {
	return docker.Network{Name: NamesOf(s.Hosted).Network, Labels: map[string]string{LabelHosted: s.Hosted.String()}}
}

// Container is the org's gateway container (HR-501). Its arguments are
// fixed: only the record id, the pinned image and the clamped limits vary.
func (s Spec) Container() (docker.Container, error) {
	if s.Hosted.IsZero() {
		return docker.Container{}, fmt.Errorf("%w: no hosted gateway", ErrProfile)
	}
	if !imageRE.MatchString(s.Image) {
		return docker.Container{}, fmt.Errorf("%w: the image is not pinned by digest", ErrProfile)
	}
	if !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) != s.Root {
		return docker.Container{}, fmt.Errorf("%w: the private directory is not an absolute clean path", ErrProfile)
	}
	if s.Runtime != docker.RuntimeRunc && s.Runtime != docker.RuntimeRunsc {
		return docker.Container{}, fmt.Errorf("%w: runtime %q", ErrProfile, s.Runtime)
	}
	n, uid := NamesOf(s.Hosted), strconv.Itoa(UID(s.Hosted))
	l := clamp(s.Limits)
	return docker.Container{
		Name:  n.Container,
		Image: s.Image,
		User:  uid + ":" + uid,
		// The image's entrypoint is the gateway; these follow it.
		Args:     []string{"serve", "--config", ConfigFile, "--hosted-token-file", TokenFile},
		Networks: []string{n.Network},
		// Nothing secret: the token is a file, never a variable (HR-502).
		Env: []string{"PC_GW_IDENTITY_DIR=" + StateDir, "PC_GW_LISTEN=0.0.0.0:" + strconv.Itoa(Port)},
		Mounts: []docker.Mount{
			{Kind: docker.Bind, Source: s.Root, Target: EnrollDir, ReadOnly: true},
			{Kind: docker.Volume, Source: n.Volume, Target: StateDir},
		},
		BindRoot: filepath.Dir(s.Root),
		Runtime:  s.Runtime,
		Limits:   docker.Limits{PIDs: l.PIDs, MemoryMiB: l.MemoryMiB, MilliCPUs: l.MilliCPUs},
		Labels:   map[string]string{LabelHosted: s.Hosted.String()},
	}, nil
}
