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

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
)

// maxMessage bounds one message the gateway writes to a connector.
const maxMessage = 1 << 20

// ErrExited reports a connector whose container stopped.
var ErrExited = errors.New("connectors: the connector's container stopped")

// Stdio is a connector's MCP transport over its container's standard input
// and output: MCP 2025-11-25 over stdio, one JSON-RPC message per line. It
// implements the gateway MCP client's Sender (upstream.Sender), so the
// client speaks to a connector as to any MCP server: each POST is written
// as one line, and the lines the server writes back until the one that
// answers it come back as an event stream. A request the server makes on
// the way (an elicitation) therefore reaches the client, which refuses it
// exactly as over HTTP (HR-082). A connector handles one exchange at a
// time (design decision 6).
type Stdio struct {
	in io.Writer
	// exchange is held from writing a request until its answer is read.
	exchange sync.Mutex
	// write serializes writes: an answer to the server is written while a
	// request's exchange is held.
	write sync.Mutex
	lines chan []byte
	done  chan struct{}
	err   error
}

// NewStdio reads the connector's lines from out until it ends; in is its
// standard input.
func NewStdio(in io.Writer, out io.Reader) *Stdio {
	s := &Stdio{in: in, lines: make(chan []byte), done: make(chan struct{})}
	go s.read(out)
	return s
}

func (s *Stdio) read(out io.Reader) {
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64<<10), egress.MaxResponse)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		s.lines <- bytes.Clone(sc.Bytes())
	}
	s.err = sc.Err()
	close(s.done)
}

// Done is closed when the connector's output ends.
func (s *Stdio) Done() <-chan struct{} { return s.done }

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
		s.exchange.Lock()
		defer s.exchange.Unlock()
		return accepted(req), s.send(ctx, line)
	}
	s.exchange.Lock()
	if err := s.send(ctx, line); err != nil {
		s.exchange.Unlock()
		return nil, err
	}
	if m.Method == "server/discover" {
		// A 2025-11-25 server has no discovery: its "method not found"
		// reads as an HTTP server's refusal, so the client speaks
		// 2025-11-25.
		defer s.exchange.Unlock()
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
		defer s.exchange.Unlock()
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
// relay when set.
func (s *Stdio) answerTo(ctx context.Context, id jsontext.Value, relay func([]byte) error) ([]byte, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.done:
			return nil, errors.Join(ErrExited, s.err)
		case l := <-s.lines:
			var e envelope
			if json.Unmarshal(l, &e) != nil {
				continue
			}
			answer := e.Method == "" && bytes.Equal(e.ID, id)
			if e.Method == "" && !answer {
				continue // a late answer to an earlier request
			}
			if relay != nil {
				if err := relay(l); err != nil {
					return nil, err
				}
			}
			if answer {
				return l, nil
			}
		}
	}
}

// send writes one line to the connector.
func (s *Stdio) send(ctx context.Context, line jsontext.Value) error {
	s.write.Lock()
	defer s.write.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-s.done:
		return ErrExited
	default:
	}
	_, err := s.in.Write(append(line, '\n'))
	return err
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
