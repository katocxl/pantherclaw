// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package relay is a campaign's model relay (G0 M25 D308, D313; HR-607,
// founder decision H6): the small proxy `pclaw redteam campaign run` starts
// beside the sandbox, outside the agent's container. It holds the customer's
// model key in this process's memory and nowhere else. It listens on a
// loopback or private address that the local gateway reaches, and takes
// requests from that gateway only. It forwards each to the one model host
// named on the run, over verified HTTPS, with every credential the request
// carried removed and the key added, and it streams the answer back.
//
// The key never reaches the agent's container, a log, an argument, the
// environment or the server. Any other host is refused, and so is a redirect,
// which could carry the request and its key elsewhere. It answers the
// simulator handshake, so the gateway treats it as a simulated connection
// (HR-221). Model traffic is not attack evidence; the relay keeps no body.
package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

// Kind is the relay's name in the simulator handshake.
const Kind = "model-relay"

// MaxBody is the most a request or an answer may carry (D313).
const MaxBody = 8 << 20

// HeaderRefused marks the relay's own refusals.
const HeaderRefused = "PC-Refused-By"

// Limits of a connection to the model host. There is no overall timeout: a
// stream lasts as long as the model writes, and the gateway bounds a call.
const (
	dialTimeout   = 10 * time.Second
	tlsTimeout    = 10 * time.Second
	answerTimeout = 2 * time.Minute
)

// credentialHeaders are removed from every request: whatever credential the
// agent found or made up never reaches the model host.
var credentialHeaders = []string{
	"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "Api-Key", "X-Auth-Token", "Private-Token", "X-Goog-Api-Key",
	"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip",
}

// answerHeaders are the only headers of the answer passed back.
var answerHeaders = []string{"Content-Type", "Cache-Control", "Retry-After", "Request-Id", "X-Request-Id"}

var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// Options configure a relay.
type Options struct {
	// Listen is an IP literal, loopback or private, with a port (0 chooses
	// one). A public or unspecified address is refused.
	Listen string
	// Gateway is the address of the only peer. Empty means this host's
	// loopback, which needs a loopback Listen.
	Gateway netip.Addr
	// ModelHost is the one host forwarded to, as a DNS name.
	ModelHost string
	// Key is the customer's key. The relay owns it: Close clears it.
	Key []byte
	// KeyHeader is the header the key goes in. "authorization" sends
	// "Bearer <key>".
	KeyHeader string
	// Roots replaces the system roots for the model host; nil uses them. A
	// test's local provider uses it.
	Roots *x509.CertPool
	// DialAddr, when set, is the host:port dialed for ModelHost, whose name
	// the certificate must still match. A test's local provider uses it.
	DialAddr string
	Log      *slog.Logger
}

// Stats is what crossed the relay: counts only.
type Stats struct {
	Requests, BytesToModel, BytesFromModel int64
}

// Relay is one run's relay.
type Relay struct {
	ln      net.Listener
	srv     *http.Server
	host    string
	self    string
	gateway netip.Addr
	header  string
	log     *slog.Logger

	mu  sync.Mutex
	key []byte

	requests, out, in atomic.Int64
	done              chan error
}

// listenAddr checks a listen address: an IP literal that is loopback or
// private, never unspecified or public.
func listenAddr(s string) (netip.Addr, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.Addr{}, errors.New("relay: the listen address must be an IP literal with a port")
	}
	a := ap.Addr().Unmap()
	if !a.IsLoopback() && !a.IsPrivate() {
		return netip.Addr{}, errors.New("relay: the listen address must be loopback or private, never a public interface")
	}
	return a, nil
}

// New starts a relay. It takes ownership of o.Key.
func New(o Options) (*Relay, error) {
	addr, err := listenAddr(o.Listen)
	if err != nil {
		return nil, err
	}
	gw := o.Gateway.Unmap()
	switch {
	case !hostRE.MatchString(o.ModelHost) || net.ParseIP(o.ModelHost) != nil || strings.Trim(o.ModelHost, "0123456789.") == "":
		return nil, errors.New("relay: the model host must be a DNS name")
	case len(o.Key) == 0:
		return nil, errors.New("relay: no model key")
	case !validKeyHeader(o.KeyHeader):
		return nil, errors.New("relay: the key header must be a plain header name")
	case gw.IsValid() && !gw.IsLoopback() && !gw.IsPrivate():
		return nil, errors.New("relay: a remote gateway is refused: the relay serves the local gateway only")
	case !gw.IsValid() && !addr.IsLoopback():
		return nil, errors.New("relay: a private listen address needs the gateway's address")
	}
	if o.Log == nil {
		o.Log = pclog.Discard()
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", o.Listen)
	if err != nil {
		return nil, fmt.Errorf("relay: %w", err)
	}
	r := &Relay{
		ln: ln, host: o.ModelHost, self: ln.Addr().String(), gateway: gw, header: http.CanonicalHeaderKey(o.KeyHeader), log: o.Log,
		key: bytes.Clone(o.Key), done: make(chan error, 1),
	}
	clear(o.Key)
	r.srv = &http.Server{
		Handler:           r.handler(transport(o)),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(pclog.Discard().Handler(), slog.LevelError),
	}
	go func() { r.done <- r.srv.Serve(ln) }()
	return r, nil
}

func validKeyHeader(h string) bool {
	if h == "" || len(h) > 64 {
		return false
	}
	for _, c := range h {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// transport reaches the model host only: no proxy from the environment
// (HR-072), verified TLS, and no client certificate.
func transport(o Options) *http.Transport {
	dialer := &net.Dialer{Timeout: dialTimeout}
	host, dial := o.ModelHost, o.DialAddr
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h, _, err := net.SplitHostPort(addr)
			if err != nil || h != host {
				return nil, errors.New("relay: only the model host is dialed")
			}
			if dial != "" {
				addr = dial
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.Roots, ServerName: host},
		TLSHandshakeTimeout:   tlsTimeout,
		ResponseHeaderTimeout: answerTimeout,
		ForceAttemptHTTP2:     true,
	}
}

// Addr is where the relay listens, as host:port.
func (r *Relay) Addr() string { return r.self }

// BaseURL is the relay's URL for its simulated connection.
func (r *Relay) BaseURL() string { return "http://" + r.self }

// Stats returns what crossed the relay so far.
func (r *Relay) Stats() Stats {
	return Stats{Requests: r.requests.Load(), BytesToModel: r.out.Load(), BytesFromModel: r.in.Load()}
}

// Close stops the relay and clears the key.
func (r *Relay) Close(ctx context.Context) error {
	err := r.srv.Shutdown(ctx)
	if err != nil {
		_ = r.srv.Close()
	}
	<-r.done
	r.mu.Lock()
	clear(r.key)
	r.key = nil
	r.mu.Unlock()
	return err
}

// Refusal is the JSON body of the relay's refusals. It never names the key.
type Refusal struct {
	Error string `json:"error"`
}

func refuse(w http.ResponseWriter, status int, code string) {
	w.Header().Set(HeaderRefused, "relay")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, Refusal{Error: code})
}

// peerAllowed reports whether a connection comes from the local gateway.
func (r *Relay) peerAllowed(remote string) bool {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	a := ap.Addr().Unmap()
	if r.gateway.IsValid() {
		return a == r.gateway
	}
	return a.IsLoopback()
}

func (r *Relay) handler(rt http.RoundTripper) http.Handler {
	target := &url.URL{Scheme: "https", Host: r.host}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(target)
			p.Out.Host = r.host
			for _, h := range credentialHeaders {
				p.Out.Header.Del(h)
			}
			p.Out.Header.Del(r.header)
			r.mu.Lock()
			key := string(r.key)
			r.mu.Unlock()
			if r.header == "Authorization" {
				key = "Bearer " + key
			}
			p.Out.Header.Set(r.header, key)
		},
		Transport:      rt,
		FlushInterval:  -1, // every write of the model goes straight on
		ModifyResponse: r.answer,
		ErrorHandler: func(w http.ResponseWriter, in *http.Request, err error) {
			// err may be anything the transport says: it stays out of the log
			// and the answer, which only say that it failed.
			code := "model_host_unreachable"
			if errors.Is(err, errRedirect) {
				code = "redirect_refused"
			}
			r.log.WarnContext(in.Context(), "relay.upstream_failed", "code", code)
			refuse(w, http.StatusBadGateway, code)
		},
		ErrorLog: slog.NewLogLogger(pclog.Discard().Handler(), slog.LevelError),
	}
	return handshake.Wrap(Kind, http.HandlerFunc(func(w http.ResponseWriter, in *http.Request) {
		switch {
		case !r.peerAllowed(in.RemoteAddr):
			refuse(w, http.StatusForbidden, "not_the_local_gateway")
		case in.Method == http.MethodConnect, in.URL.IsAbs() && !strings.EqualFold(in.URL.Hostname(), r.host), !r.ownHost(in.Host):
			r.log.WarnContext(in.Context(), "relay.refused", "code", "other_host_refused")
			refuse(w, http.StatusForbidden, "other_host_refused")
		case in.Header.Get("Upgrade") != "":
			refuse(w, http.StatusForbidden, "upgrade_refused")
		default:
			r.requests.Add(1)
			in.Body = &counted{ReadCloser: http.MaxBytesReader(w, in.Body, MaxBody), n: &r.out}
			proxy.ServeHTTP(w, in)
		}
	}))
}

// ownHost reports whether a request names the relay or the model host: an
// address for another host is refused, not silently sent to the model.
func (r *Relay) ownHost(h string) bool {
	if strings.EqualFold(h, r.self) {
		return true
	}
	if name, _, err := net.SplitHostPort(h); err == nil {
		h = name
	}
	return strings.EqualFold(h, r.host)
}

var errRedirect = errors.New("relay: the model host redirected")

// answer checks the answer. A redirect is refused, since following it, or
// handing it to the gateway, could send the request elsewhere. Only an
// allow-list of headers goes back, none that holds the key, and the body
// passes through a filter that removes the key if the host echoes it.
func (r *Relay) answer(res *http.Response) error {
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return errRedirect
	}
	r.mu.Lock()
	key := bytes.Clone(r.key)
	r.mu.Unlock()
	kept := http.Header{}
	for _, h := range answerHeaders {
		if v := res.Header.Values(h); len(v) > 0 && !strings.Contains(strings.Join(v, ","), string(key)) {
			kept[h] = v
		}
	}
	res.Header = kept
	res.ContentLength = -1
	res.Body = &bounded{redactor: redactor{src: res.Body, key: key}, n: &r.in}
	return nil
}

type counted struct {
	io.ReadCloser
	n *atomic.Int64
}

func (c *counted) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// bounded cuts an answer at MaxBody and counts what passed.
type bounded struct {
	redactor
	sent int64
	n    *atomic.Int64
}

func (b *bounded) Read(p []byte) (int, error) {
	if b.sent >= MaxBody {
		return 0, errors.New("relay: the answer is over the limit")
	}
	if left := MaxBody - b.sent; int64(len(p)) > left {
		p = p[:left]
	}
	n, err := b.redactor.Read(p)
	b.sent += int64(n)
	b.n.Add(int64(n))
	return n, err
}

// redactMark replaces the key if a host echoes it.
const redactMark = "[REDACTED]"

// redactor removes the key from a stream, across reads. It holds back only a
// tail that could be the start of the key, so a stream stays a stream: a
// chunk waits for the next one only while its end looks like the key.
type redactor struct {
	src     io.ReadCloser
	key     []byte
	pending []byte
	ready   []byte
	err     error
}

func (r *redactor) Close() error {
	clear(r.key)
	return r.src.Close()
}

func (r *redactor) Read(p []byte) (int, error) {
	for len(r.ready) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		buf := make([]byte, 32<<10)
		n, err := r.src.Read(buf)
		r.err = err
		r.pending = append(r.pending, buf[:n]...)
		r.pending = bytes.ReplaceAll(r.pending, r.key, []byte(redactMark))
		hold := 0
		if err == nil {
			hold = heldTail(r.pending, r.key)
		}
		cut := len(r.pending) - hold
		r.ready = append(r.ready, r.pending[:cut]...)
		r.pending = append(r.pending[:0], r.pending[cut:]...)
	}
	n := copy(p, r.ready)
	r.ready = r.ready[n:]
	return n, nil
}

// heldTail is the length of the longest tail of b that is a proper start of
// key.
func heldTail(b, key []byte) int {
	for n := min(len(key)-1, len(b)); n > 0; n-- {
		if bytes.Equal(b[len(b)-n:], key[:n]) {
			return n
		}
	}
	return 0
}
