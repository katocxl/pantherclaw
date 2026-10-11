// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcpsim

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"strconv"
)

// maxLine bounds one stdio message.
const maxLine = 8 << 20

// ServeStdio serves MCP 2025-11-25 over stdio (one JSON-RPC message per
// line, no session) on r and w until r ends or ctx does: the transport of
// a connector a customer-hosted gateway runs in a container (G0 M9 track
// C). It has no discovery, as a 2025-11-25 server has none. With Faults.Ask
// set, each tools/call first asks the client for each method and reads its
// answer.
func (s *Server) ServeStdio(ctx context.Context, r io.Reader, w io.Writer) error {
	in := bufio.NewScanner(r)
	in.Buffer(make([]byte, 0, 64<<10), maxLine)
	send := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, err = w.Write(append(b, '\n'))
		return err
	}
	read := func() (message, error) {
		for in.Scan() {
			if err := ctx.Err(); err != nil {
				return message{}, err
			}
			var m message
			if json.Unmarshal(in.Bytes(), &m) == nil {
				return m, nil
			}
		}
		if err := in.Err(); err != nil {
			return message{}, err
		}
		return message{}, io.EOF
	}
	for {
		m, err := read()
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		if len(m.ID) == 0 || m.Method == "" {
			continue // a notification, or an answer nobody waits for
		}
		var out map[string]any
		switch m.Method {
		case "initialize":
			out = reply(m.ID, map[string]any{
				"protocolVersion": Legacy, "capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]string{"name": "pantherclaw-mcp-simulator", "version": "1.0.0"},
			}, nil)
		case "tools/list":
			out = reply(m.ID, s.page(m.Params), nil)
		case "tools/call":
			if err := s.askStdio(send, read); err != nil {
				return err
			}
			result, rpcErr := s.call(ctx, m.Params)
			out = reply(m.ID, result, rpcErr)
		default:
			out = reply(m.ID, nil, rpcError(-32601, "Method not found"))
		}
		if err := send(out); err != nil {
			return err
		}
	}
}

// askStdio sends the client each of Faults.Ask and reads its answers.
func (s *Server) askStdio(send func(any) error, read func() (message, error)) error {
	for i, method := range s.f.Ask {
		rid := "srv-" + strconv.Itoa(i) + "-" + newID()[:8]
		if err := send(map[string]any{"jsonrpc": "2.0", "id": rid, "method": method, "params": map[string]any{"message": "Simulated request"}}); err != nil {
			return err
		}
		for {
			m, err := read()
			if err != nil {
				return err
			}
			var id string
			if m.Method != "" || json.Unmarshal(m.ID, &id) != nil || id != rid {
				continue
			}
			ans := m.Result
			if len(m.Error) > 0 {
				ans = m.Error
			}
			s.mu.Lock()
			s.answers = append(s.answers, method+": "+summarize(ans))
			s.mu.Unlock()
			break
		}
	}
	return nil
}
