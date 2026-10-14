// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package canary is the containment sandbox's external canary (G0 M9
// decision 2, HR-121). It runs outside the sandbox, on the host by default:
// pclaw runs it in its own process for each session, and `pantherclaw-sim
// canary` runs the same canary on its own. It listens on a DNS port (UDP
// and TCP), an HTTPS port and an SSH port and records every hit that
// carries a run's marker, the marker derived from that run's report nonce
// (report.Marker). A probe run on the sandbox network must leave no hit; the
// control run on an open network must leave one, which shows the canary
// would have seen a leak. Report signs what it saw with the session's probe
// key.
package canary

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

// maxHits bounds the hits kept; the oldest go first.
const maxHits = 10000

// markerRE finds markers in what arrives: "pc" and 32 hex digits, short
// enough for a DNS label.
var markerRE = regexp.MustCompile(`pc[0-9a-f]{32}`)

// Ports are the canary's ports. Zero picks a free one.
type Ports struct {
	DNS, HTTPS, SSH int
}

// Canary records hits.
type Canary struct {
	mu   sync.Mutex
	hits []report.Hit
	log  *slog.Logger
}

// New returns a canary with no hits.
func New(log *slog.Logger) *Canary {
	return &Canary{log: log}
}

func (c *Canary) record(payload []byte, proto string, port int, from string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range markerRE.FindAll(payload, 8) {
		if len(c.hits) >= maxHits {
			c.hits = c.hits[1:]
		}
		c.hits = append(c.hits, report.Hit{Proto: proto, Port: port, Marker: string(m), At: time.Now().UTC()})
		c.log.Warn("canary.hit", "marker", string(m), "proto", proto, "port", port, "from", from)
	}
}

// Hits returns the hits carrying one of markers, oldest first.
func (c *Canary) Hits(markers ...string) []report.Hit {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []report.Hit{}
	for _, h := range c.hits {
		for _, m := range markers {
			if h.Marker == m {
				out = append(out, h)
			}
		}
	}
	return out
}

// Listen opens the canary on host: TCP on every port, UDP on the DNS port.
// It serves until ctx ends and returns the ports it got.
func (c *Canary) Listen(ctx context.Context, host string, p Ports) (Ports, error) {
	var lc net.ListenConfig
	var ls []net.Listener
	var got [3]int
	for i, port := range [3]int{p.DNS, p.HTTPS, p.SSH} {
		l, err := lc.Listen(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			for _, l := range ls {
				_ = l.Close()
			}
			return Ports{}, err
		}
		ls = append(ls, l)
		got[i] = l.Addr().(*net.TCPAddr).Port
	}
	pc, err := lc.ListenPacket(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(got[0])))
	if err != nil {
		for _, l := range ls {
			_ = l.Close()
		}
		return Ports{}, err
	}
	for i, l := range ls {
		go c.serveTCP(ctx, l, got[i])
	}
	go c.serveUDP(ctx, pc, got[0])
	return Ports{DNS: got[0], HTTPS: got[1], SSH: got[2]}, nil
}

// serveTCP records what each connection sends first (4 KiB, 2 s) and
// answers like an HTTP server, so that HTTP clients finish.
func (c *Canary) serveTCP(ctx context.Context, l net.Listener, port int) {
	go func() { <-ctx.Done(); _ = l.Close() }()
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			b, _ := io.ReadAll(io.LimitReader(conn, 4<<10))
			c.record(b, "tcp", port, conn.RemoteAddr().String())
			_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
		}()
	}
}

// serveUDP records every datagram: a DNS query carries the marker as a
// label.
func (c *Canary) serveUDP(ctx context.Context, pc net.PacketConn, port int) {
	go func() { <-ctx.Done(); _ = pc.Close() }()
	buf := make([]byte, 2048)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			continue
		}
		c.record(buf[:n], "udp", port, from.String())
	}
}

// Report signs the canary's report for a session: base carries the
// session, a fresh server nonce and the session's facts; the hits are those
// of markers (the probe run's and the control run's).
func (c *Canary) Report(key ed25519.PrivateKey, base report.Report, markers ...string) (string, error) {
	base.Kind, base.Results = report.KindCanary, []report.Result{}
	base.Canary = report.Canary{Hits: c.Hits(markers...)}
	if len(base.Canary.Hits) > report.MaxHits {
		base.Canary.Hits = base.Canary.Hits[:report.MaxHits]
	}
	return report.Sign(key, base)
}

// QueryHandler answers GET /hits/{marker} with the hits carrying it, for a
// canary run on its own (pantherclaw-sim canary).
func (c *Canary) QueryHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /hits/{marker}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, c.Hits(r.PathValue("marker")))
	})
	return mux
}
