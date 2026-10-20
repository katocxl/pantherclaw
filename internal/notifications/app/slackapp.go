// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Slack approval cards (G0 M14 D22, D23; HR-313..315). A slack_app channel
// holds a bot token (its encrypted secret) and sends it only to Slack's
// Web API, to four methods: auth.test and conversations.info when the
// channel is activated, chat.postMessage and chat.update when a card is
// posted, closed or escalated. Nothing comes back from Slack into
// PantherClaw but these answers, and no answer decides anything.

// SlackAPI is Slack's Web API base URL, the only place a bot token goes.
const SlackAPI = "https://slack.com/api"

// slackMaxAnswer bounds how much of a Slack answer is read (D88).
const slackMaxAnswer = 1 << 20

// slackMethods are the only methods a bot token is sent to.
var slackMethods = map[string]bool{
	"auth.test": true, "conversations.info": true, "chat.postMessage": true, "chat.update": true,
}

var (
	slackTokenPattern   = regexp.MustCompile(`^xoxb-[A-Za-z0-9-]{20,250}$`)
	slackChannelPattern = regexp.MustCompile(`^[CG][A-Z0-9]{8,12}$`)
	slackErrorPattern   = regexp.MustCompile(`^[a-z0-9_]{1,48}$`)
	slackTSPattern      = regexp.MustCompile(`^[0-9]{10}\.[0-9]{6}$`)
	slackTeamPattern    = regexp.MustCompile(`^T[A-Z0-9]{4,30}$`)
	slackBotPattern     = regexp.MustCompile(`^B[A-Z0-9]{4,30}$`)
)

// ErrSlackAPIBase refuses a Slack API base that is not Slack's own or a
// loopback simulator.
var ErrSlackAPIBase = errors.New("notifications: the Slack API base must be https://slack.com/api or a loopback simulator")

// SetSlackAPI points slack_app channels at a simulator (dev and tests
// only): base must be an http(s) URL on a loopback address, and client the
// client that reaches it. Production keeps Slack's own API through the
// egress client.
func (s *Service) SetSlackAPI(base string, client *http.Client) error {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ErrSlackAPIBase
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return ErrSlackAPIBase
	}
	if client == nil {
		return ErrSlackAPIBase
	}
	s.slackBase, s.slackHTTP = strings.TrimSuffix(base, "/"), client
	return nil
}

// slackAnswer is the part of a Slack answer PantherClaw reads.
type slackAnswer struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error"`
	TS     string `json:"ts"`
	TeamID string `json:"team_id"`
	Team   string `json:"team"`
	BotID  string `json:"bot_id"`
	User   string `json:"user"`
	// Channel is an object in conversations.info answers and an id in
	// chat answers.
	Channel jsontext.Value `json:"channel"`
}

// slackChannel is a conversations.info channel.
type slackChannel struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Member    bool   `json:"is_member"`
	ExtShared bool   `json:"is_ext_shared"`
	Shared    bool   `json:"is_shared"`
	Archived  bool   `json:"is_archived"`
}

// slackRevoked are Slack's errors for a token or channel that no longer
// works: the channel is paused rather than retried.
var slackRevoked = map[string]bool{
	"invalid_auth": true, "not_authed": true, "account_inactive": true, "token_revoked": true, "token_expired": true,
	"channel_not_found": true, "is_archived": true, "not_in_channel": true, "missing_scope": true, "team_access_not_granted": true,
}

// slackTransient are Slack's errors worth retrying.
var slackTransient = map[string]bool{
	"ratelimited": true, "internal_error": true, "fatal_error": true, "service_unavailable": true, "request_timeout": true,
}

// slackCall sends one Web API request with the bot token: JSON body for the
// chat methods, a query for conversations.info. Redirects are refused, the
// answer is read up to 4 KiB, and Slack's error is kept only as a code.
func (s *Service) slackCall(ctx context.Context, token, method string, body any, query url.Values) (slackAnswer, outcome) {
	if !slackMethods[method] || !slackTokenPattern.MatchString(token) {
		return slackAnswer{}, outcome{code: "slack_refused", permanent: true}
	}
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	target := s.slackBase + "/" + method
	httpMethod, reader := http.MethodPost, io.Reader(http.NoBody)
	if query != nil {
		httpMethod, target = http.MethodGet, target+"?"+query.Encode()
	} else {
		b, err := json.Marshal(body)
		if err != nil {
			return slackAnswer{}, outcome{code: "encode_failed", permanent: true}
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, httpMethod, target, reader)
	if err != nil {
		return slackAnswer{}, outcome{code: "bad_url", permanent: true}
	}
	if query == nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.slackHTTP.Do(req)
	if err != nil {
		switch {
		case errors.Is(err, httpx.ErrDestinationDenied):
			return slackAnswer{}, outcome{code: "destination_denied"}
		case errors.Is(err, context.DeadlineExceeded):
			return slackAnswer{}, outcome{code: "timeout"}
		}
		return slackAnswer{}, outcome{code: "connection_failed"}
	}
	defer func() { _ = resp.Body.Close() }()
	head, _ := io.ReadAll(io.LimitReader(resp.Body, slackMaxAnswer))
	out := outcome{status: resp.StatusCode}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		out.code, out.retryAfter = "rate_limited", retryAfter(resp.Header.Get("Retry-After"))
		return slackAnswer{}, out
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		out.code = "redirect_refused"
		return slackAnswer{}, out
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		out.code = "http_" + strconv.Itoa(resp.StatusCode)
		return slackAnswer{}, out
	}
	var a slackAnswer
	if err := json.Unmarshal(head, &a); err != nil {
		out.code = "slack_bad_answer"
		return slackAnswer{}, out
	}
	if !a.OK {
		code := a.Error
		if !slackErrorPattern.MatchString(code) {
			code = "unknown"
		}
		out.code = "slack_" + code
		switch {
		case slackRevoked[code]:
			out.gone = true
		case slackTransient[code]:
			out.retryAfter = retryAfter(resp.Header.Get("Retry-After"))
		default:
			out.permanent = true
		}
		return a, out
	}
	out.ok = true
	return a, out
}

func retryAfter(h string) time.Duration {
	if secs, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && secs > 0 {
		return min(time.Duration(secs)*time.Second, domain.MaxRetryAfter)
	}
	return 0
}

// slackPost posts a card (or a thread reply) and returns its ts.
func (s *Service) slackPost(ctx context.Context, token, channel, threadTS string, c domain.SlackCard) (string, outcome) {
	body := map[string]any{"channel": channel, "text": c.Text, "unfurl_links": false, "unfurl_media": false}
	if len(c.Blocks) > 0 {
		body["blocks"] = c.Blocks
	}
	if threadTS != "" {
		body["thread_ts"] = threadTS
	}
	a, out := s.slackCall(ctx, token, "chat.postMessage", body, nil)
	if out.ok && !slackTSPattern.MatchString(a.TS) {
		return "", outcome{code: "slack_bad_answer", status: out.status}
	}
	return a.TS, out
}

// slackUpdate replaces a card in place.
func (s *Service) slackUpdate(ctx context.Context, token, channel, ts string, c domain.SlackCard) outcome {
	// chat.update keeps the old blocks unless blocks is sent: a closed
	// card sends an empty list so its button is gone.
	body := map[string]any{"channel": channel, "ts": ts, "text": c.Text, "blocks": c.Blocks}
	if c.Blocks == nil {
		body["blocks"] = []domain.SlackBlock{}
	}
	_, out := s.slackCall(ctx, token, "chat.update", body, nil)
	return out
}

// SlackWorkspace is what Slack reports when a slack_app channel is checked:
// ids, and names as Slack gives them (untrusted text, shown escaped).
type SlackWorkspace struct {
	TeamID, TeamName, BotID, BotName, ChannelName string
}

// Slack check errors (activation and token replacement).
var (
	ErrSlackToken    = errors.New("notifications: Slack refused the bot token")
	ErrSlackChannel  = errors.New("notifications: the Slack channel does not exist or the bot is not a member")
	ErrSlackExternal = errors.New("notifications: the Slack channel is shared outside the workspace")
	ErrSlackDown     = errors.New("notifications: Slack could not be reached")
)

// checkSlack runs auth.test and conversations.info with token for channel
// (D22): the token works, and the channel exists, is not archived, has the
// bot as a member and is not shared with another organization.
func (s *Service) checkSlack(ctx context.Context, token, channel string) (SlackWorkspace, error) {
	if !slackTokenPattern.MatchString(token) || !slackChannelPattern.MatchString(channel) {
		return SlackWorkspace{}, ErrSlackToken
	}
	a, out := s.slackCall(ctx, token, "auth.test", map[string]any{}, nil)
	switch {
	case out.ok && slackTeamPattern.MatchString(a.TeamID) && slackBotPattern.MatchString(a.BotID):
	case out.ok || out.gone || out.permanent:
		return SlackWorkspace{}, ErrSlackToken
	default:
		return SlackWorkspace{}, ErrSlackDown
	}
	w := SlackWorkspace{TeamID: a.TeamID, TeamName: domain.CardValue(a.Team), BotID: a.BotID, BotName: domain.CardValue(a.User)}
	a, out = s.slackCall(ctx, token, "conversations.info", nil, url.Values{"channel": {channel}})
	var c slackChannel
	switch {
	case out.ok && json.Unmarshal(a.Channel, &c) == nil && c.ID == channel:
	case out.ok || out.gone || out.permanent:
		return SlackWorkspace{}, ErrSlackChannel
	default:
		return SlackWorkspace{}, ErrSlackDown
	}
	switch {
	case c.ExtShared || c.Shared:
		return SlackWorkspace{}, ErrSlackExternal
	case !c.Member || c.Archived:
		return SlackWorkspace{}, ErrSlackChannel
	}
	w.ChannelName = domain.CardValue(c.Name)
	return w, nil
}

// approvalRequestOf is the request a card is about: the id in the
// notice's approval-page link (every card type links there).
func approvalRequestOf(linkPath string) (ids.UUID, bool) {
	rest, ok := strings.CutPrefix(linkPath, "/approvals/")
	if !ok {
		return ids.UUID{}, false
	}
	id, err := ids.ParseUUID(rest)
	return id, err == nil
}

// sendSlackApp delivers one notice to a slack_app channel: the open card
// for a new request, an update in place when it ends, a thread reply when
// it is escalated (D23). Every card is rendered from the request as it is
// now, so a late or repeated delivery shows the current state; a request
// that returned to PENDING after its card closed gets a new card (D104).
// Below the Team edition no new card is posted, but cards already posted
// are still closed (D88).
func (s *Service) sendSlackApp(ctx context.Context, org ids.OrgID, d dbq.LoadDeliveryRow, link string) outcome {
	ev := domain.CardEventOf(d.Type)
	if d.ChannelID == nil {
		return outcome{code: "no_channel", permanent: true}
	}
	if ev != domain.CardClose {
		if ok, err := s.slackApprovals(ctx); err != nil {
			return outcome{code: "edition_unavailable"}
		} else if !ok {
			return outcome{skip: true, code: "edition"}
		}
	}
	var cfg dbq.GetSlackAppChannelRow
	var facts dbq.SlackCardFactsRow
	var stored *dbq.PcSlackCard
	request, isRequest := approvalRequestOf(d.LinkPath)
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if cfg, err = q.GetSlackAppChannel(ctx, org, *d.ChannelID); err != nil {
			return err
		}
		if ev == domain.CardTest || ev == domain.CardNone || !isRequest {
			return nil
		}
		if facts, err = q.SlackCardFacts(ctx, org, request); err != nil {
			return err
		}
		c, err := q.LatestSlackCard(ctx, org, request, *d.ChannelID)
		if err == nil {
			stored = &c
		} else if !db.IsNoRows(err) {
			return err
		}
		return nil
	}, db.ReadOnly())
	switch {
	case db.IsNoRows(err):
		return outcome{skip: true, code: "no_card_subject"}
	case err != nil:
		return outcome{code: "load_failed"}
	case cfg.State != SlackActive && ev != domain.CardClose:
		return outcome{skip: true, code: "channel_pending"}
	case ev == domain.CardNone:
		return outcome{skip: true, code: "not_a_card"}
	case ev != domain.CardTest && !isRequest:
		return outcome{skip: true, code: "no_card_subject"}
	}
	token, err := s.openSecret(ctx, org, d, secretColumn, cfg.Secret)
	if err != nil {
		return outcome{code: "secret_unavailable"}
	}
	simulated := strings.HasPrefix(d.Title, domain.SimulatedPrefix)
	if ev == domain.CardTest {
		_, out := s.slackPost(ctx, string(token), cfg.SlackChannel, "", domain.TestCard(simulated))
		return out
	}
	f := domain.CardFacts{
		Level: cfg.DataLevel, Kind: facts.SubjectKind, Consequence: facts.Reversibility, State: facts.State,
		ExpiresAt: facts.DeadlineAt, RequestID: request.String(), Link: link, Simulated: simulated,
		Operation: facts.Operation, Agent: facts.AgentName, Environment: facts.EnvironmentName,
	}
	// A request waiting again after its card closed (a voided approval
	// returned it to PENDING) gets a new card; the closed one stays closed.
	reopened := stored != nil && stored.State == domain.CardClosed && !domain.CardIsClosed(facts.State)
	switch ev {
	case domain.CardPost:
		if stored != nil && !reopened {
			return s.slackExisting(ctx, org, string(token), *stored, f)
		}
		if cfg.ActivatedAt == nil || facts.CreatedAt.Before(*cfg.ActivatedAt) {
			// Cards only for requests made after the channel was activated
			// with its current token (D66): no backfill.
			return outcome{skip: true, code: "before_activation"}
		}
		return s.slackNewCard(ctx, org, string(token), cfg, f, request)
	case domain.CardClose:
		if stored == nil || reopened {
			return outcome{skip: true, code: "no_card"}
		}
		return s.slackExisting(ctx, org, string(token), *stored, f)
	case domain.CardEscalate:
		if stored == nil || stored.State != domain.CardOpen || stored.Ts == nil {
			return outcome{skip: true, code: "no_open_card"}
		}
		return s.slackEscalate(ctx, org, string(token), *stored)
	case domain.CardTest, domain.CardNone:
	}
	return outcome{skip: true, code: "not_a_card"}
}

// slackEscalate claims the next escalation reply of an open card, then
// posts it (D104): a concurrent delivery never posts the same step twice;
// a reply Slack refused releases the claim, a lost answer keeps it.
func (s *Service) slackEscalate(ctx context.Context, org ids.OrgID, token string, stored dbq.PcSlackCard) outcome {
	var claimed int64
	if err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		claimed, err = dbq.New(tx).ClaimSlackEscalation(ctx, org, stored.CardID, stored.Escalations)
		return err
	}); err != nil {
		return outcome{code: "store_failed"}
	}
	if claimed == 0 {
		// Another notice claimed this step: this one is the next step, tried
		// again with the count it will then read (D117).
		return outcome{code: "escalation_claimed", contended: true}
	}
	_, out := s.slackPost(ctx, token, stored.SlackChannel, *stored.Ts, domain.EscalationReply(int(stored.Escalations)+1))
	if !out.ok && !slackRefused(out) {
		// The reply may be in Slack: its claim stays and it is never posted
		// again under another number (D117).
		return outcome{code: "slack_post_unknown", status: out.status, permanent: true}
	}
	if !out.ok && slackRefused(out) {
		_ = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := dbq.New(tx).ReleaseSlackEscalation(ctx, org, stored.CardID, stored.Escalations+1)
			return err
		})
	}
	return out
}

// card renders f as the request is now: open while it waits, closed once
// it is final.
func card(f domain.CardFacts) (domain.SlackCard, string) {
	if domain.CardIsClosed(f.State) {
		return domain.ClosedCard(f), domain.CardClosed
	}
	return domain.OpenCard(f), domain.CardOpen
}

// Card claim states besides OPEN and CLOSED (D88, D104).
const (
	cardPosting  = "POSTING"
	cardUnknown  = "UNKNOWN"
	cardOrphaned = "ORPHANED"
)

// slackExisting handles a notice for a request that already has a card:
// an OPEN or CLOSED card is updated to the request's current state; a
// claim found from an earlier attempt, whose answer was lost, is UNKNOWN
// and never posted again (F167: the approval page is authoritative). An
// ORPHANED card is still updated: a later notice may reach it (D117).
func (s *Service) slackExisting(ctx context.Context, org ids.OrgID, token string, stored dbq.PcSlackCard, f domain.CardFacts) outcome {
	switch stored.State {
	case cardPosting:
		_ = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := dbq.New(tx).MarkSlackCardUnknown(ctx, org, stored.CardID)
			return err
		})
		return outcome{code: "slack_post_unknown", permanent: true}
	case cardUnknown:
		return outcome{code: "slack_post_unknown", permanent: true}
	}
	return s.slackRefresh(ctx, org, token, stored, f)
}

// slackRefused reports whether a failed post certainly posted nothing:
// Slack refused it (an HTTP status or an "ok": false answer it gave), or
// the egress guard refused the destination before any byte was sent. A
// lost answer, a 5xx or an unreadable 2xx may have posted.
func slackRefused(out outcome) bool {
	switch {
	case out.code == "destination_denied":
		return true
	case out.status == 0 || out.status >= 500 || out.code == "slack_bad_answer":
		return false
	}
	return true
}

// slackNewCard claims the request's card in this channel, posts it and
// stores its ts (D88). A post Slack refused releases the claim for the
// retry; a post whose answer was lost leaves the card UNKNOWN. After
// storing, it reads the request again: a decision that came between the
// first read and the store found no card to close, so the card is closed
// here.
func (s *Service) slackNewCard(ctx context.Context, org ids.OrgID, token string, cfg dbq.GetSlackAppChannelRow, f domain.CardFacts, request ids.UUID) outcome {
	cardID := ids.NewV7()
	var claimed int64
	if err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		claimed, err = dbq.New(tx).ClaimSlackCard(ctx, dbq.ClaimSlackCardParams{
			OrgID: org, CardID: cardID, RequestID: request, ChannelRecordID: cfg.ChannelRecordID, SlackChannel: cfg.SlackChannel,
		})
		return err
	}); err != nil {
		return outcome{code: "store_failed"}
	}
	if claimed == 0 {
		return outcome{skip: true, code: "card_claimed"} // another delivery posts it
	}
	c, state := card(f)
	ts, out := s.slackPost(ctx, token, cfg.SlackChannel, "", c)
	if !out.ok {
		_ = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			q := dbq.New(tx)
			if slackRefused(out) {
				_, err := q.ReleaseSlackCard(ctx, org, cardID)
				return err
			}
			_, err := q.MarkSlackCardUnknown(ctx, org, cardID)
			return err
		})
		if !slackRefused(out) {
			return outcome{code: "slack_post_unknown", status: out.status, permanent: true}
		}
		return out
	}
	stored := dbq.PcSlackCard{
		OrgID: org, CardID: cardID, RequestID: request, ChannelRecordID: cfg.ChannelRecordID, SlackChannel: cfg.SlackChannel, Ts: &ts, State: state,
	}
	var err error
	for range 3 { // the post is done: storing its ts is retried, never the post
		if err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := dbq.New(tx).SetSlackCardPosted(ctx, dbq.SetSlackCardPostedParams{Ts: &ts, State: state, OrgID: org, CardID: cardID})
			return err
		}); err == nil {
			break
		}
	}
	if err != nil {
		return outcome{code: "store_failed"} // the retry finds the claim and marks it UNKNOWN
	}
	var now string
	if err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).SlackCardFacts(ctx, org, request)
		now = r.State
		return err
	}, db.ReadOnly()); err != nil {
		return out // posted and stored; the reconciler closes it if it ends
	}
	if domain.CardIsClosed(now) != domain.CardIsClosed(f.State) {
		f.State = now
		return s.slackRefresh(ctx, org, token, stored, f)
	}
	return out
}

// slackRefresh updates a stored card to the request's current state. It
// reads the request again after the update: when it changed between open
// and closed meanwhile (a stale close racing a reopen), the card is updated
// once more to what is now true (D117).
func (s *Service) slackRefresh(ctx context.Context, org ids.OrgID, token string, stored dbq.PcSlackCard, f domain.CardFacts) outcome {
	if stored.Ts == nil {
		return outcome{skip: true, code: "no_card"}
	}
	var out outcome
	for range 2 {
		c, state := card(f)
		out = s.slackUpdate(ctx, token, stored.SlackChannel, *stored.Ts, c)
		if !out.ok {
			return out
		}
		if state != stored.State {
			if err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
				return dbq.New(tx).SetSlackCardState(ctx, state, org, stored.CardID)
			}); err != nil {
				return outcome{code: "store_failed"}
			}
			stored.State = state
		}
		var now string
		if err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			r, err := dbq.New(tx).SlackCardFacts(ctx, org, stored.RequestID)
			now = r.State
			return err
		}, db.ReadOnly()); err != nil || domain.CardIsClosed(now) == domain.CardIsClosed(f.State) {
			return out
		}
		f.State = now
	}
	return out
}

// slackApprovals reports whether the edition offers Slack approval cards
// (Team and above, D22); without an edition source, Community applies.
func (s *Service) slackApprovals(ctx context.Context) (bool, error) {
	if s.editions == nil {
		return false, nil
	}
	e, err := s.editions.Current(ctx)
	if err != nil {
		return false, err
	}
	return e.SlackApprovals(), nil
}
