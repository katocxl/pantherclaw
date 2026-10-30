// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package teams is a simulated Microsoft Teams bot service for tests and
// demos (pantherclaw-sim teams, G0 M20 D254). It serves the two parts a
// Bot Framework bot talks to, as Microsoft documents them:
//
//   - the Microsoft Entra token endpoint, POST /{tenant}/oauth2/v2.0/token
//     (botframework.com for a multi-tenant bot), which issues an access
//     token for the client-credentials grant and scope
//     https://api.botframework.com/.default;
//   - the Bot Connector service under /teams/ (the service URL): the
//     conversations the bot is part of, the channels of a team, a
//     conversation's paged members, a new channel conversation (POST
//     /v3/conversations), an activity in a conversation and an activity
//     update.
//
// Every Bot Connector request must carry a token this simulator issued and
// that has not expired. A channel can be marked shared with another tenant
// (a member of another tenant, or a guest), and faults inject 429s, a
// refused client, an expired token and a blocked bot. GET /__sim/messages
// lists what was posted and how many tokens were issued, for tests. Every
// response is marked SIMULATED; nothing here reaches Microsoft.
package teams

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

// Simulated identities.
const (
	// TenantID is the host tenant the bot is installed in.
	TenantID = "5a1e0000-0000-4000-8000-000000000001"
	// OtherTenantID is a partner tenant whose people a shared channel admits.
	OtherTenantID = "5a1e0000-0000-4000-8000-000000000002"
	// AppID is the bot's Microsoft App ID (its client id).
	AppID = "5a1e0000-0000-4000-8000-0000000000b0"
	// TeamID is the simulated team; its General channel has the same id.
	TeamID = "19:simulatedteam00000000000000000@thread.tacv2"
	// Scope is the only scope the token endpoint issues tokens for.
	Scope = "https://api.botframework.com/.default"
	// TokenLifetime is how long an issued token is accepted.
	TokenLifetime = time.Hour
)

// maxBody bounds a request body.
const maxBody = 64 << 10

var (
	// ChannelPattern is a Teams channel (conversation) id.
	ChannelPattern = regexp.MustCompile(`^19:[0-9A-Za-z_-]{1,64}@thread\.(tacv2|skype)$`)
	tenantPattern  = regexp.MustCompile(`^(botframework\.com|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
)

// Member is one member of a channel, as the Bot Connector lists it.
type Member struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	TenantID string `json:"tenantId"`
	// UserRole is user, guest or anonymous.
	UserRole string `json:"userRole"`
}

// Channel is one channel of the simulated team.
type Channel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Installed: the bot was added to the channel and may post.
	Installed bool     `json:"installed"`
	Members   []Member `json:"members"`
}

// Faults configures fault injection.
type Faults struct {
	// RateLimit answers the next RateLimit Bot Connector requests with 429
	// and Retry-After: RetryAfter seconds (default 1).
	RateLimit  int `json:"rate_limit,omitzero"`
	RetryAfter int `json:"retry_after,omitzero"`
	// InvalidClient refuses every token request (a deleted or rotated
	// client secret): 401 invalid_client.
	InvalidClient bool `json:"invalid_client,omitzero"`
	// ExpireTokens treats every issued token as expired: 401.
	ExpireTokens bool `json:"expire_tokens,omitzero"`
	// Blocked answers every post 403 MessageWritesBlocked (the bot was
	// uninstalled or blocked).
	Blocked bool `json:"blocked,omitzero"`
}

// Require is what a token request must carry.
type Require struct {
	// ClientID and ClientSecret are the only client accepted; an empty
	// ClientID accepts any.
	ClientID, ClientSecret string
}

// Message is one activity the bot posted.
type Message struct {
	Conversation string `json:"conversation"`
	Channel      string `json:"channel"`
	ActivityID   string `json:"activity_id"`
	Type         string `json:"type"`
	Text         string `json:"text,omitzero"`
	// Attachments are the activity's attachments as sent (raw JSON), such
	// as an Adaptive Card.
	Attachments jsontext.Value `json:"attachments,omitzero"`
	Updates     int            `json:"updates"`
}

// Calls counts requests per route, refused ones included.
type Calls map[string]int

// Server is the simulated Teams bot service.
type Server struct {
	require Require
	log     *slog.Logger

	mu       sync.Mutex
	faults   Faults
	channels map[string]Channel
	messages []Message
	calls    Calls
	issued   map[string]time.Time
	used     []string
	now      func() time.Time
	seq      int
}

// New returns a simulator with the given channels.
func New(channels []Channel, f Faults, log *slog.Logger) *Server {
	s := &Server{faults: f, log: log, channels: map[string]Channel{}, calls: Calls{}, issued: map[string]time.Time{}, now: time.Now}
	for _, c := range channels {
		s.channels[c.ID] = c
	}
	return s
}

// WithRequire sets what token requests must carry, and returns the server.
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

// SetChannel adds or replaces a channel (a test shares one with another
// tenant).
func (s *Server) SetChannel(c Channel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.channels[c.ID] = c
}

// SetClock replaces the clock tokens expire by.
func (s *Server) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// Messages returns a copy of every posted activity, in order.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.messages)
}

// Calls returns how many requests each route received.
func (s *Server) Calls() Calls {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.calls)
}

// Issued returns how many tokens the token endpoint issued.
func (s *Server) Issued() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.issued)
}

// Used returns the token of every authorized Bot Connector request, in
// order.
func (s *Server) Used() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.used)
}

// Handler serves the simulator.
func (s *Server) Handler() http.Handler {
	return handshake.Wrap("teams", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Simulated", "true")
		switch p := r.URL.Path; {
		case p == "/__sim/messages" && r.Method == http.MethodGet:
			s.mu.Lock()
			issued := len(s.issued)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"messages": s.Messages(), "calls": s.Calls(), "tokens_issued": issued})
		case p == "/__sim/faults" && r.Method == http.MethodPost:
			var f Faults
			if err := json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &f); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.SetFaults(f)
			w.WriteHeader(http.StatusNoContent)
		case p == "/__sim/channels" && r.Method == http.MethodPost:
			var c Channel
			if err := json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &c); err != nil || !ChannelPattern.MatchString(c.ID) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.SetChannel(c)
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(p, "/oauth2/v2.0/token") && r.Method == http.MethodPost:
			s.token(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/"), "/oauth2/v2.0/token"))
		case strings.HasPrefix(p, "/teams/v3/"):
			s.connector(w, r)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// token answers the client-credentials grant.
func (s *Server) token(w http.ResponseWriter, r *http.Request, tenant string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls["token"]++
	r.Body = http.MaxBytesReader(nil, r.Body, maxBody)
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") || r.ParseForm() != nil ||
		!tenantPattern.MatchString(tenant) {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request"))
		return
	}
	f := r.PostForm
	switch {
	case f.Get("grant_type") != "client_credentials":
		writeJSON(w, http.StatusBadRequest, oauthError("unsupported_grant_type"))
		return
	case f.Get("scope") != Scope:
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_scope"))
		return
	case s.faults.InvalidClient || f.Get("client_id") == "" || f.Get("client_secret") == "" ||
		(s.require.ClientID != "" && (f.Get("client_id") != s.require.ClientID ||
			subtle.ConstantTimeCompare([]byte(f.Get("client_secret")), []byte(s.require.ClientSecret)) != 1)):
		writeJSON(w, http.StatusUnauthorized, oauthError("invalid_client"))
		return
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	tok := "simtok-" + hex.EncodeToString(b)
	s.issued[tok] = s.now().Add(TokenLifetime)
	writeJSON(w, http.StatusOK, map[string]any{
		"token_type": "Bearer", "expires_in": int(TokenLifetime / time.Second), "ext_expires_in": int(TokenLifetime / time.Second),
		"access_token": tok,
	})
}

// connector answers one Bot Connector request.
func (s *Server) connector(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.EscapedPath(), "/teams/v3/"), "/")
	for i, p := range parts {
		v, err := url.PathUnescape(p)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, connectorError("BadSyntax", "path"))
			return
		}
		parts[i] = v
	}
	route := routeOf(r.Method, parts)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[route]++
	if s.faults.RateLimit > 0 {
		s.faults.RateLimit--
		after := s.faults.RetryAfter
		if after <= 0 {
			after = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(after))
		writeJSON(w, http.StatusTooManyRequests, connectorError("TooManyRequests", "slow down"))
		return
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	exp, issued := s.issued[tok]
	if !ok || !issued || s.faults.ExpireTokens || !s.now().Before(exp) {
		writeJSON(w, http.StatusUnauthorized, connectorError("Unauthorized", "the bearer token is missing, unknown or expired"))
		return
	}
	s.used = append(s.used, tok)
	switch route {
	case "conversations.list":
		s.conversations(w)
	case "team.channels":
		s.teamChannels(w, parts[1])
	case "conversation.members":
		s.members(w, r, parts[1])
	case "conversation.create":
		s.create(w, r)
	case "activity.send":
		s.send(w, r, parts[1])
	case "activity.update":
		s.update(w, r, parts[1], parts[3])
	default:
		writeJSON(w, http.StatusNotFound, connectorError("NotFound", "no such route"))
	}
}

// routeOf names a Bot Connector request's route ("" for none).
func routeOf(method string, p []string) string {
	switch {
	case method == http.MethodGet && len(p) == 1 && p[0] == "conversations":
		return "conversations.list"
	case method == http.MethodGet && len(p) == 3 && p[0] == "teams" && p[2] == "conversations":
		return "team.channels"
	case method == http.MethodGet && len(p) == 3 && p[0] == "conversations" && p[2] == "pagedmembers":
		return "conversation.members"
	case method == http.MethodPost && len(p) == 1 && p[0] == "conversations":
		return "conversation.create"
	case method == http.MethodPost && len(p) == 3 && p[0] == "conversations" && p[2] == "activities":
		return "activity.send"
	case method == http.MethodPut && len(p) == 4 && p[0] == "conversations" && p[2] == "activities":
		return "activity.update"
	}
	return "unknown"
}

// conversations lists the conversations the bot is part of (Bot Framework
// "Get Conversations"): every channel it was added to.
func (s *Server) conversations(w http.ResponseWriter) {
	out := []map[string]any{}
	for _, id := range slices.Sorted(maps.Keys(s.channels)) {
		if s.channels[id].Installed {
			out = append(out, map[string]any{"id": id, "isGroup": true})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"conversations": out})
}

func (s *Server) teamChannels(w http.ResponseWriter, team string) {
	if team != TeamID {
		writeJSON(w, http.StatusNotFound, connectorError("NotFound", "the bot is not installed in this team"))
		return
	}
	out := []map[string]any{}
	for _, id := range slices.Sorted(maps.Keys(s.channels)) {
		c := s.channels[id]
		name := any(c.Name)
		if c.ID == TeamID {
			name = nil // the General channel's name is null, for localization
		}
		out = append(out, map[string]any{"id": c.ID, "name": name})
	}
	writeJSON(w, http.StatusOK, map[string]any{"conversations": out})
}

// members answers a channel's paged members: pageSize 50..500, a
// continuation token for the next page.
func (s *Server) members(w http.ResponseWriter, r *http.Request, conversation string) {
	c, ok := s.channel(w, conversation)
	if !ok {
		return
	}
	size := 200
	if v := r.URL.Query().Get("pageSize"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 50 || n > 500 {
			writeJSON(w, http.StatusBadRequest, connectorError("BadArgument", "pageSize must be 50..500"))
			return
		}
		size = n
	}
	start := 0
	if v := r.URL.Query().Get("continuationToken"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > len(c.Members) {
			writeJSON(w, http.StatusBadRequest, connectorError("BadArgument", "continuationToken"))
			return
		}
		start = n
	}
	end := min(start+size, len(c.Members))
	out := map[string]any{"members": c.Members[start:end]}
	if end < len(c.Members) {
		out["continuationToken"] = strconv.Itoa(end)
	}
	writeJSON(w, http.StatusOK, out)
}

// channel returns an installed channel, or writes the Bot Connector's error.
func (s *Server) channel(w http.ResponseWriter, id string) (Channel, bool) {
	c, ok := s.channels[id]
	switch {
	case !ok:
		writeJSON(w, http.StatusNotFound, connectorError("ConversationNotFound", "conversation not found"))
		return Channel{}, false
	case !c.Installed:
		writeJSON(w, http.StatusForbidden, connectorError("BotNotInConversationRoster", "the bot is not part of the conversation roster"))
		return Channel{}, false
	}
	return c, true
}

// activity is the part of an activity the simulator reads.
type activity struct {
	Type        string         `json:"type"`
	Text        string         `json:"text"`
	Attachments jsontext.Value `json:"attachments"`
}

// create starts a new reply chain in a channel: isGroup true and the
// channel in channelData, as Microsoft documents for a channel conversation.
func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IsGroup     bool `json:"isGroup"`
		ChannelData struct {
			Channel struct {
				ID string `json:"id"`
			} `json:"channel"`
			Tenant struct {
				ID string `json:"id"`
			} `json:"tenant"`
		} `json:"channelData"`
		Activity *activity `json:"activity"`
	}
	if !isJSON(r) || json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &in) != nil || !in.IsGroup || in.Activity == nil {
		writeJSON(w, http.StatusBadRequest, connectorError("BadArgument", "a channel conversation needs isGroup, channelData.channel.id and an activity"))
		return
	}
	if in.ChannelData.Tenant.ID != "" && in.ChannelData.Tenant.ID != TenantID {
		writeJSON(w, http.StatusForbidden, connectorError("Forbidden", "another tenant"))
		return
	}
	c, ok := s.channel(w, in.ChannelData.Channel.ID)
	if !ok {
		return
	}
	m, ok := s.post(w, c, c.ID, *in.Activity)
	if !ok {
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": m.Conversation, "activityId": m.ActivityID})
}

// send posts an activity into a conversation: a channel's id starts a new
// reply chain; a reply chain's id ("<channel>;messageid=<id>") replies.
func (s *Server) send(w http.ResponseWriter, r *http.Request, conversation string) {
	var in activity
	if !isJSON(r) || json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &in) != nil {
		writeJSON(w, http.StatusBadRequest, connectorError("BadArgument", "an activity"))
		return
	}
	channel, _, _ := strings.Cut(conversation, ";messageid=")
	c, ok := s.channel(w, channel)
	if !ok {
		return
	}
	m, ok := s.post(w, c, conversation, in)
	if !ok {
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": m.ActivityID})
}

func (s *Server) post(w http.ResponseWriter, c Channel, conversation string, in activity) (Message, bool) {
	switch {
	case s.faults.Blocked:
		writeJSON(w, http.StatusForbidden, map[string]any{"errorCode": 209, "message": `{"subCode":"MessageWritesBlocked"}`})
		return Message{}, false
	case in.Type != "message" || (in.Text == "" && len(in.Attachments) == 0):
		writeJSON(w, http.StatusBadRequest, connectorError("BadArgument", "a message activity with text or attachments"))
		return Message{}, false
	}
	s.seq++
	id := fmt.Sprintf("%d%03d", s.now().UnixMilli(), s.seq%1000)
	if conversation == c.ID {
		conversation = c.ID + ";messageid=" + id
	}
	m := Message{Conversation: conversation, Channel: c.ID, ActivityID: id, Type: in.Type, Text: in.Text, Attachments: in.Attachments}
	s.messages = append(s.messages, m)
	s.log.Info("sim.teams_posted", slog.String("channel", c.ID), slog.String("activity", id))
	return m, true
}

func (s *Server) update(w http.ResponseWriter, r *http.Request, conversation, id string) {
	var in activity
	if !isJSON(r) || json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &in) != nil || in.Type != "message" {
		writeJSON(w, http.StatusBadRequest, connectorError("BadArgument", "a message activity"))
		return
	}
	for i := range s.messages {
		m := &s.messages[i]
		if m.ActivityID == id && (m.Conversation == conversation || m.Channel == conversation) {
			m.Text, m.Attachments = in.Text, in.Attachments
			m.Updates++
			writeJSON(w, http.StatusOK, map[string]any{"id": id})
			return
		}
	}
	writeJSON(w, http.StatusNotFound, connectorError("ActivityNotFound", "activity not found"))
}

func isJSON(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
}

func oauthError(code string) map[string]any {
	return map[string]any{"error": code, "error_description": "SIMULATED: " + code}
}

func connectorError(code, message string) map[string]any {
	return map[string]any{"error": map[string]any{"code": code, "message": "SIMULATED: " + message}}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
}
