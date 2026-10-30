// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package canary

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

// waitHits waits until the canary has n hits for marker.
func waitHits(t *testing.T, c *Canary, marker string, n int) []report.Hit {
	t.Helper()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(5 * time.Second)
	for {
		if h := c.Hits(marker); len(h) >= n {
			return h
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatalf("the canary has %d hits for %s, want %d", len(c.Hits(marker)), marker, n)
		}
	}
}

func TestHR121_TheCanaryRecordsMarkersOnEveryPort(t *testing.T) {
	c := New(pclog.Discard())
	p, err := c.Listen(t.Context(), "127.0.0.1", Ports{})
	if err != nil {
		t.Fatal(err)
	}
	m := report.Marker("nonce-of-the-probe-run")
	if !markerRE.MatchString(m) || m == report.Marker("another-nonce") {
		t.Fatalf("marker %q", m)
	}
	for _, port := range []int{p.DNS, p.HTTPS, p.SSH} {
		conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(conn, "SSH-2.0-probe %s\r\n", m)
		_ = conn.Close()
	}
	// A DNS query carries the marker as a label.
	u, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p.DNS)))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = u.Write(append([]byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, byte(len(m))}, m+"\x06canary\x00\x00\x01\x00\x01"...))
	_ = u.Close()
	hits := waitHits(t, c, m, 4)
	protos := map[string]int{}
	for _, h := range hits {
		protos[h.Proto+":"+strconv.Itoa(h.Port)]++
	}
	for _, want := range []string{"tcp:" + strconv.Itoa(p.DNS), "tcp:" + strconv.Itoa(p.HTTPS), "tcp:" + strconv.Itoa(p.SSH), "udp:" + strconv.Itoa(p.DNS)} {
		if protos[want] != 1 {
			t.Errorf("hits %v lack %s", protos, want)
		}
	}
	if len(c.Hits(report.Marker("unseen"))) != 0 {
		t.Fatal("hits for a marker that never arrived")
	}

	srv := httptest.NewServer(c.QueryHandler())
	defer srv.Close()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/hits/"+m, nil)
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var got []report.Hit
	_ = json.UnmarshalRead(res.Body, &got)
	_ = res.Body.Close()
	if len(got) != 4 {
		t.Fatalf("query: %d hits", len(got))
	}
}

// TestHR121_AChosenDNSPortTakenOnUDPIsAnError: a free port is tried again
// only when the system picks it; a configured port is what it says.
func TestHR121_AChosenDNSPortTakenOnUDPIsAnError(t *testing.T) {
	var lc net.ListenConfig
	taken, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = taken.Close() }()
	port := taken.LocalAddr().(*net.UDPAddr).Port
	if _, err := New(pclog.Discard()).Listen(t.Context(), "127.0.0.1", Ports{DNS: port}); err == nil {
		t.Fatal("a configured DNS port taken on UDP was accepted")
	}
}

// TestHR215_TheCanaryReportIsSignedWithTheSessionKey: the canary's report
// carries the hits of the session's markers only, signed with the probe
// key.
func TestHR215_TheCanaryReportIsSignedWithTheSessionKey(t *testing.T) {
	c := New(pclog.Discard())
	probe, control, other := report.Marker("probe-nonce-0001"), report.Marker("control-nonce-01"), report.Marker("other-session-01")
	c.record([]byte("GET /"+control+" HTTP/1.1"), "tcp", 18443, "x")
	c.record([]byte(other), "udp", 18453, "y")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	at := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	compact, err := c.Report(key, report.Report{
		Format: report.Format, Session: "s-1", Nonce: "canary-nonce-0123456789", StartedAt: at, FinishedAt: at,
		Engine: report.Engine{Version: "29.8.2", APIVersion: "1.56", Runtime: "runc"},
	}, probe, control)
	if err != nil {
		t.Fatal(err)
	}
	r, err := report.Verify(compact, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != report.KindCanary || len(r.Canary.Hits) != 1 || r.Canary.Hits[0].Marker != control || strings.Contains(compact, other) {
		t.Fatalf("canary report %+v", r)
	}
}

func TestTheCanaryKeepsABoundedNumberOfHits(t *testing.T) {
	c := New(pclog.Discard())
	first := fmt.Sprintf("pc%032x", 0)
	for i := range maxHits + 5 {
		c.record(fmt.Appendf(nil, "pc%032x", i), "tcp", 1, "x")
	}
	if len(c.Hits(first)) != 0 || len(c.Hits(fmt.Sprintf("pc%032x", maxHits+4))) != 1 || len(c.hits) != maxHits {
		t.Fatalf("kept %d", len(c.hits))
	}
}
