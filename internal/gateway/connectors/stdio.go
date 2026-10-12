// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package connectors runs a customer-hosted gateway's connector connections
// (G0 M9 track C; HR-084, HR-216, decision 5): third-party stdio MCP
// servers, each in a hardened container the gateway's host process starts
// through the Docker CLI, which the gateway speaks MCP to over the
// container's standard input and output.
package connectors

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
)

// maxMessage bounds one message the gateway writes to a connector.
const maxMessage = 1 << 20

// Errors of a connector's transport.
var (
	// ErrExited reports a connector whose container stopped.
	ErrExited = errors.New("connectors: the connector's container stopped")
	// ErrBroken reports a connector whose exchange was abandoned (a call
	// that timed out, a write that never went through, an answer over the
	// limit): it may still be working on it, so it takes no other call and
	// is replaced (G0 M9 design decision 6).
	ErrBroken = errors.New("connectors: the connector's last exchange was abandoned; it is being replaced")
)

// Stdio is a connector's MCP transport over its container's standard input
// and output: MCP 2025-11-25 over stdio, one JSON-RPC message per line. It
// implements the gateway MCP client's Sender (upstream.Sender), so the
// client speaks to a connector as to any MCP server: each POST is written
// as one line, and the lines the server writes back until the one that
// answers it come back as an event stream. A request the server makes on
// the way (an elicitation) therefore reaches the client, which refuses it
// exactly as over HTTP (HR-082). A connector handles one exchange at a
// time (design decision 6). An exchange that is abandoned leaves the
// Stdio broken: Usable reports false and every later call fails, until the
// supervisor replaces the container.
type Stdio struct {
	in io.Writer
	// max bounds the lines one exchange reads (the connection's
	// max_response_bytes).
	max int64
	// exchange is held from writing a request until its answer is read;
	// write serializes writes (an answer to the server is written while a
	// request's exchange is held). Both are taken with the caller's
	// context.
	exchange chan struct{}
	write    chan struct{}
	// reading is set while an exchange reads; the reader drops lines that
	// come outside one (a late answer, a stray notification).
	reading atomic.Bool
	broken  atomic.Bool
	lines   chan []byte
	done    chan struct{}
	stop    chan struct{}
	closed  sync.Once
	err     error
}

// NewStdio reads the connector's lines from out until it ends; in is its
// standard input, and limit bounds the lines one exchange reads.
func NewStdio(in io.Writer, out io.Reader, limit int64) *Stdio {
	if limit <= 0 || limit > egress.MaxResponse {
		limit = egress.MaxResponse
	}
	s := &Stdio{
		in: in, max: limit, exchange: make(chan struct{}, 1), write: make(chan struct{}, 1), lines: make(chan []byte, 16),
		done: make(chan struct{}), stop: make(chan struct{}),
	}
	go s.read(out)
	return s
}

func (s *Stdio) read(out io.Reader) {
	defer close(s.done)
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64<<10), int(s.max))
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 || !s.reading.Load() {
			continue
		}
		select {
		case s.lines <- bytes.Clone(sc.Bytes()):
		case <-s.stop:
			return
		}
	}
	s.err = sc.Err()
}

// Done is closed when the connector's output ends.
func (s *Stdio) Done() <-chan struct{} { return s.done }

// Usable reports whether the connector can take a call: its output has not
// ended and no exchange was abandoned.
func (s *Stdio) Usable() bool {
	select {
	case <-s.done:
		return false
	default:
		return !s.broken.Load()
	}
}

// Close stops reading and leaves the Stdio broken. The supervisor calls it
// when it stops the container, which closes the connector's input.
func (s *Stdio) Close() {
	s.broken.Store(true)
	s.closed.Do(func() { close(s.stop) })
}

// take takes a lock with the caller's context.
func (s *Stdio) take(ctx context.Context, lock chan struct{}) error {
	select {
	case lock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return ErrExited
	case <-s.stop:
		return ErrBroken
	}
}

type envelope struct {
	ID     jsontext.Value `json:"id,omitzero"`
	Method string         `json:"method,omitzero"`
	Error  *struct {
		Code int `json:"code"`
	} `json:"error,omitzero"`
}

// Open implements upstream.Sender.
func (s *Stdio) Open(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if s.broken.Load() {
		return nil, ErrBroken
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxMessage+1))
	if err != nil || len(body) > maxMessage {
		return nil, fmt.Errorf("connectors: an MCP message over the limit")
	}
	var m envelope
	line := jsontext.Value(bytes.Clone(body))
	if json.Unmarshal(body, &m) != nil || line.Compact() != nil {
		return nil, errors.New("connectors: not a JSON-RPC message")
	}
	switch {
	case m.Method == "":
		// The client's answer to a request of the server's, mid-exchange.
		return accepted(req), s.send(ctx, line)
	case len(m.ID) == 0:
		if err := s.take(ctx, s.exchange); err != nil {
			return nil, err
		}
		defer func() { <-s.exchange }()
		return accepted(req), s.send(ctx, line)
	}
	if err := s.take(ctx, s.exchange); err != nil {
		return nil, err
	}
	s.reading.Store(true)
	release := func() {
		s.reading.Store(false)
		<-s.exchange
	}
	if err := s.send(ctx, line); err != nil {
		release()
		return nil, err
	}
	if m.Method == "server/discover" {
		// A 2025-11-25 server has no discovery: its "method not found"
		// reads as an HTTP server's refusal, so the client speaks
		// 2025-11-25.
		defer release()
		answer, err := s.answerTo(ctx, m.ID, nil)
		if err != nil {
			return nil, err
		}
		var a envelope
		_ = json.Unmarshal(answer, &a)
		status := http.StatusOK
		if a.Error != nil && a.Error.Code == -32601 {
			status = http.StatusBadRequest
		}
		return response(req, status, "application/json", io.NopCloser(bytes.NewReader(answer))), nil
	}
	pr, pw := io.Pipe()
	go func() {
		defer release()
		_, err := s.answerTo(ctx, m.ID, func(l []byte) error {
			_, err := fmt.Fprintf(pw, "data: %s\n\n", l)
			return err
		})
		pw.CloseWithError(err)
	}()
	return response(req, http.StatusOK, "text/event-stream", pr), nil
}

// answerTo reads lines until the answer to id, passing each line it
// relays (the server's requests and notifications, then the answer) to
// relay when set. Any way out but the answer leaves the Stdio broken: the
// connector may still be working on the request.
func (s *Stdio) answerTo(ctx context.Context, id jsontext.Value, relay func([]byte) error) (answer []byte, err error) {
	defer func() {
		if err != nil {
			s.broken.Store(true)
		}
	}()
	var read int64
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.done:
			return nil, errors.Join(ErrExited, s.err)
		case <-s.stop:
			return nil, ErrBroken
		case l := <-s.lines:
			if read += int64(len(l)); read > s.max {
				return nil, fmt.Errorf("connectors: the connector's answer is over %d bytes", s.max)
			}
			var e envelope
			if json.Unmarshal(l, &e) != nil {
				continue
			}
			isAnswer := e.Method == "" && bytes.Equal(e.ID, id)
			if e.Method == "" && !isAnswer {
				continue // a late answer to an earlier request
			}
			if relay != nil {
				if err := relay(l); err != nil {
					return nil, err
				}
			}
			if isAnswer {
				return l, nil
			}
		}
	}
}

// send writes one line to the connector. A write that does not go through
// before the caller's context ends, or fails, leaves the Stdio broken: the
// connector may have read part of it.
func (s *Stdio) send(ctx context.Context, line jsontext.Value) error {
	if err := s.take(ctx, s.write); err != nil {
		return err
	}
	defer func() { <-s.write }()
	select {
	case <-s.done:
		return ErrExited
	default:
	}
	errc := make(chan error, 1)
	go func() {
		_, err := s.in.Write(append(line, '\n'))
		errc <- err
	}()
	select {
	case err := <-errc:
		if err != nil {
			s.broken.Store(true)
		}
		return err
	case <-ctx.Done():
		s.broken.Store(true)
		return ctx.Err()
	case <-s.done:
		s.broken.Store(true)
		return ErrExited
	}
}

func accepted(req *http.Request) *http.Response {
	return response(req, http.StatusAccepted, "", http.NoBody)
}

func response(req *http.Request, status int, contentType string, body io.ReadCloser) *http.Response {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	return &http.Response{StatusCode: status, Header: h, Body: body, Request: req, ProtoMajor: 1, ProtoMinor: 1}
}
