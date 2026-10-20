// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package slack is a simulated Slack Web API for tests and demos
// (pantherclaw-sim slack, G0 M14 D24). It answers the four methods
// PantherClaw uses — auth.test, conversations.info, chat.postMessage and
// chat.update — under /api/, the way Slack does: HTTP 200 with "ok" true or
// false and an error code, and HTTP 429 with Retry-After when rate limited.
// Every request must carry a bot token (Bearer xoxb-...), and the one in
// Require when one is set. It can mark channels externally shared or the
// bot not a member, and inject 429s, invalid_auth and channel_not_found.
// GET /__sim/messages lists what was posted, for tests. Every response is
// marked SIMULATED; nothing here reaches Slack.
package slack

import (
	"crypto/subtle"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

// Workspace identity answered by auth.test.
const (
	TeamID = "T0SIMULATED"
	BotID  = "B0SIMULATED"
	UserID = "U0SIMULATED"
)

// maxBody bounds a request body.
const maxBody = 64 << 10

var (
	channelPattern = regexp.MustCompile(`^[CG][A-Z0-9]{8,12}$`)
	tsPattern      = regexp.MustCompile(`^[0-9]{10}\.[0-9]{6}$`)
)

// Channel is one channel of the simulated workspace.
type Channel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Private channels have a G id.
	Private bool `json:"is_private"`
	// ExtShared: shared with another organization (Slack Connect).
	ExtShared bool `json:"is_ext_shared"`
	// Shared: shared with another workspace.
	Shared bool `json:"is_shared"`
	// Member: the bot is in the channel and may post.
	Member bool `json:"is_member"`
}

// Faults configures fault injection.
type Faults struct {
	// RateLimit answers the next RateLimit requests with 429 and
	// Retry-After: RetryAfter seconds (default 1).
	RateLimit  int `json:"rate_limit,omitzero"`
	RetryAfter int `json:"retry_after,omitzero"`
	// InvalidAuth answers every request {"ok":false,"error":"invalid_auth"}
	// (a revoked token).
	InvalidAuth bool `json:"invalid_auth,omitzero"`
	// ChannelNotFound answers every channel method with channel_not_found
	// (a deleted channel).
	ChannelNotFound bool `json:"channel_not_found,omitzero"`
	// DropAnswer posts the next DropAnswer messages and then closes the
	// connection without answering (a lost answer, D88).
	DropAnswer int `json:"drop_answer,omitzero"`
}

// Require is what a request must carry.
type Require struct {
	// Token is the only bot token accepted; empty accepts any xoxb- token.
	Token string
}

// Message is one posted message with its current content. Updates count
// the chat.update calls that changed it.
type Message struct {
	Channel  string `json:"channel"`
	TS       string `json:"ts"`
	ThreadTS string `json:"thread_ts,omitzero"`
	Text     string `json:"text"`
	// Blocks is the message's Block Kit blocks as sent (raw JSON).
	Blocks  jsontext.Value `json:"blocks,omitzero"`
	Updates int            `json:"updates"`
	// UnfurlLinks and UnfurlMedia are the unfurl arguments as sent ("" when
	// left out).
	UnfurlLinks string `json:"unfurl_links,omitzero"`
	UnfurlMedia string `json:"unfurl_media,omitzero"`
	// Reactions are the emoji people added to the message in Slack.
	Reactions []string `json:"reactions,omitzero"`
}

// Calls counts requests per method, refused ones included.
type Calls map[string]int

// Server is the simulated Slack Web API.
type Server struct {
	require Require
	log     *slog.Logger

	mu       sync.Mutex
	faults   Faults
	channels map[string]Channel
	messages []Message
	calls    Calls
	tokens   []string
	team     string
	now      func() time.Time
	seq      int
}

// New returns a simulator with the given channels.
func New(channels []Channel, f Faults, log *slog.Logger) *Server {
	s := &Server{faults: f, log: log, channels: map[string]Channel{}, calls: Calls{}, now: time.Now, team: TeamID}
	for _, c := range channels {
		s.channels[c.ID] = c
	}
	return s
}

// WithRequire sets what requests must carry, and returns the server.
func (s *Server) WithRequire(r Require) *Server {
	s.require = r
	return s
}

// SetFaults replaces the faults from the next request on.
func (s *Server) SetFaults(f Faults) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = f
}

// SetChannel adds or replaces a channel (a test shares one externally).
func (s *Server) SetChannel(c Channel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.channels[c.ID] = c
}

// SetTeam changes the workspace auth.test reports (a token of another
// workspace).
func (s *Server) SetTeam(team string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.team = team
}

// React adds a person's reaction to a message, as Slack would show it;
// nothing is sent anywhere (a range scenario's forged approval, D91).
func (s *Server) React(channel, ts, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.messages {
		if m := &s.messages[i]; m.Channel == channel && m.TS == ts {
			m.Reactions = append(m.Reactions, name)
			return true
		}
	}
	return false
}

// Tokens returns the bot token of every authorized request, in order.
func (s *Server) Tokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.tokens)
}

// Messages returns a copy of every message, in posting order.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.messages)
}

// Calls returns how many requests each method received.
func (s *Server) Calls() Calls {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.calls)
}

// Handler serves the simulator.
func (s *Server) Handler() http.Handler {
	return handshake.Wrap("slack", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Simulated", "true")
		switch {
		case r.URL.Path == "/__sim/messages" && r.Method == http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]any{"messages": s.Messages(), "calls": s.Calls()})
		case r.URL.Path == "/__sim/faults" && r.Method == http.MethodPost:
			var f Faults
			if err := json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &f); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.SetFaults(f)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/__sim/channels" && r.Method == http.MethodPost:
			var c Channel
			if err := json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &c); err != nil || !channelPattern.MatchString(c.ID) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.SetChannel(c)
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/api/"):
			s.api(w, r, strings.TrimPrefix(r.URL.Path, "/api/"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// api answers one Web API method.
func (s *Server) api(w http.ResponseWriter, r *http.Request, method string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[method]++
	if s.faults.RateLimit > 0 {
		s.faults.RateLimit--
		after := s.faults.RetryAfter
		if after <= 0 {
			after = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(after))
		writeJSON(w, http.StatusTooManyRequests, fail("ratelimited"))
		return
	}
	if !s.authorized(r) {
		writeJSON(w, http.StatusOK, fail("not_authed"))
		return
	}
	s.tokens = append(s.tokens, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if s.faults.InvalidAuth {
		writeJSON(w, http.StatusOK, fail("invalid_auth"))
		return
	}
	in, err := params(r)
	if err != nil {
		writeJSON(w, http.StatusOK, fail("invalid_arguments"))
		return
	}
	switch method {
	case "auth.test":
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "url": "https://simulated.slack.test/", "team": "Simulated", "user": "pantherclaw",
			"team_id": s.team, "user_id": UserID, "bot_id": BotID,
		})
	case "conversations.info":
		c, code := s.channel(in.str("channel"))
		if code != "" {
			writeJSON(w, http.StatusOK, fail(code))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "channel": map[string]any{
			"id": c.ID, "name": c.Name, "is_channel": !c.Private, "is_group": c.Private, "is_private": c.Private,
			"is_member": c.Member, "is_ext_shared": c.ExtShared, "is_shared": c.Shared || c.ExtShared, "is_archived": false,
		}})
	case "chat.postMessage":
		if s.faults.DropAnswer > 0 {
			s.faults.DropAnswer--
			s.post(httptest.NewRecorder(), in)
			drop(w)
			return
		}
		s.post(w, in)
	case "chat.update":
		s.update(w, in)
	default:
		writeJSON(w, http.StatusOK, fail("unknown_method"))
	}
}

func (s *Server) authorized(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !strings.HasPrefix(tok, "xoxb-") {
		return false
	}
	return s.require.Token == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(s.require.Token)) == 1
}

// channel returns a channel the bot can see, or Slack's error code.
func (s *Server) channel(id string) (Channel, string) {
	c, ok := s.channels[id]
	if s.faults.ChannelNotFound || !ok {
		return Channel{}, "channel_not_found"
	}
	return c, ""
}

func (s *Server) post(w http.ResponseWriter, in input) {
	c, code := s.channel(in.str("channel"))
	switch {
	case code != "":
	case !c.Member:
		code = "not_in_channel"
	case in.str("text") == "" && len(in.raw("blocks")) == 0:
		code = "no_text"
	case in.str("thread_ts") != "" && !tsPattern.MatchString(in.str("thread_ts")):
		code = "invalid_thread_ts"
	}
	if code != "" {
		writeJSON(w, http.StatusOK, fail(code))
		return
	}
	s.seq++
	m := Message{
		Channel: c.ID, TS: fmt.Sprintf("%d.%06d", s.now().Unix(), s.seq%1000000), ThreadTS: in.str("thread_ts"),
		Text: in.str("text"), Blocks: in.raw("blocks"),
		UnfurlLinks: string(in.raw("unfurl_links")), UnfurlMedia: string(in.raw("unfurl_media")),
	}
	s.messages = append(s.messages, m)
	s.log.Info("sim.slack_posted", slog.String("channel", m.Channel), slog.String("ts", m.TS))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "channel": m.Channel, "ts": m.TS})
}

func (s *Server) update(w http.ResponseWriter, in input) {
	c, code := s.channel(in.str("channel"))
	if code != "" {
		writeJSON(w, http.StatusOK, fail(code))
		return
	}
	ts := in.str("ts")
	for i := range s.messages {
		m := &s.messages[i]
		if m.Channel != c.ID || m.TS != ts {
			continue
		}
		m.Text, m.Blocks = in.str("text"), in.raw("blocks")
		m.Updates++
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "channel": m.Channel, "ts": m.TS})
		return
	}
	writeJSON(w, http.StatusOK, fail("message_not_found"))
}

// input is a request's arguments: a JSON object, or form and query values.
type input struct {
	obj  map[string]jsontext.Value
	form url.Values
}

func (in input) str(k string) string {
	if in.obj != nil {
		var v string
		if raw, ok := in.obj[k]; ok && json.Unmarshal(raw, &v) == nil {
			return v
		}
		return ""
	}
	return in.form.Get(k)
}

func (in input) raw(k string) jsontext.Value {
	if in.obj != nil {
		return in.obj[k]
	}
	if v := in.form.Get(k); v != "" {
		return jsontext.Value(v)
	}
	return nil
}

func params(r *http.Request) (input, error) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var obj map[string]jsontext.Value
		if err := json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &obj); err != nil {
			return input{}, err
		}
		if obj == nil {
			obj = map[string]jsontext.Value{}
		}
		return input{obj: obj}, nil
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		return input{}, err
	}
	return input{form: r.Form}, nil
}

func fail(code string) map[string]any { return map[string]any{"ok": false, "error": code} }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
}

// drop closes the connection without an answer.
func drop(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			_ = conn.Close()
			return
		}
	}
	panic(http.ErrAbortHandler)
}
