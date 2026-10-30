// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Teams approval cards (G0 M20 D256; HR-529). A teams_app channel holds
// the org's Bot Framework bot: its app id in the configuration and its
// client secret as the channel's encrypted secret. The secret goes only to
// Microsoft Entra's token endpoint, for a token minted per send and never
// stored; the token goes only to the configured Bot Framework service URL.
// A channel is stored PENDING_ACTIVATION and becomes ACTIVE only with an
// Org Admin's fresh step-up, after the bot's token is minted and the
// channel's members are read: a member of another tenant, or a guest,
// makes it shared and it is refused. An ACTIVE channel posts one
// link-only Adaptive Card per waiting request; nothing comes back. The
// members are read again before each card: a channel found shared returns
// to PENDING_ACTIVATION, audited, the org's admins are told, and no card
// goes (D277).

// TeamsLogin is Microsoft Entra's token endpoint base.
const TeamsLogin = "https://login.microsoftonline.com"

// teamsScope is the Bot Framework scope of the client-credentials grant.
const teamsScope = "https://api.botframework.com/.default"

// teamsServiceHosts are the Bot Framework service hosts a card may go to.
var teamsServiceHosts = []string{"smba.trafficmanager.net"}

var teamsTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)

// Teams errors.
var (
	ErrTeamsBase    = errors.New("notifications: the Teams endpoints must be Microsoft's or a loopback simulator")
	ErrTeamsRefused = pcerr.New(pcerr.FailedPrecondition, "TEAMS_BOT_REFUSED", "Microsoft refused the bot's client id or secret")
	ErrTeamsChannel = pcerr.New(pcerr.FailedPrecondition, "TEAMS_CHANNEL_REFUSED",
		"the Teams channel does not exist or the bot is not in it")
	ErrTeamsShared = pcerr.New(pcerr.FailedPrecondition, "TEAMS_CHANNEL_SHARED",
		"the Teams channel has members of another tenant or guests; approval cards go only to internal channels")
	ErrTeamsUnread = pcerr.New(pcerr.FailedPrecondition, "TEAMS_CHANNEL_UNREAD",
		"Teams did not list the channel's members with their tenants and roles, so it cannot be shown internal")
	ErrTeamsUnavailable = pcerr.New(pcerr.Unavailable, "TEAMS_UNAVAILABLE", "Teams could not be reached; try again")
	ErrNotTeamsApp      = pcerr.New(pcerr.FailedPrecondition, "NOT_A_TEAMS_APP", "only Teams app channels are activated here")
	ErrTeamsState       = pcerr.New(pcerr.FailedPrecondition, "TEAMS_CHANNEL_STATE", "the Teams app channel is not pending activation")
)

// SetTeamsAPI points teams_app channels at a simulator (dev and tests
// only): base, on a loopback address reached by client, serves the token
// endpoint and, under /teams/, the Bot Connector in place of every
// channel's configured service URL (which must still be a Bot Framework
// host).
func (s *Service) SetTeamsAPI(base string, client *http.Client) error {
	if !loopbackURL(base) || client == nil {
		return ErrTeamsBase
	}
	base = strings.TrimSuffix(base, "/")
	s.teamsLogin, s.teamsHTTP, s.teamsService = base, client, base+"/teams/"
	return nil
}

func loopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

// teamsServiceOK reports whether a channel's service URL is a Bot
// Framework host over HTTPS.
func (s *Service) teamsServiceOK(service string) bool {
	u, err := url.Parse(service)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range teamsServiceHosts {
		if host == h {
			return true
		}
	}
	return strings.HasSuffix(host, ".botframework.com")
}

func (s *Service) teamsClient() *http.Client {
	if s.teamsHTTP != nil {
		return s.teamsHTTP
	}
	return s.http
}

func (s *Service) teamsLoginBase() string {
	if s.teamsLogin != "" {
		return s.teamsLogin
	}
	return TeamsLogin
}

// teamsToken mints a Bot Framework token for the channel's bot; nothing
// keeps it.
func (s *Service) teamsToken(ctx context.Context, tenant, appID string, secret []byte) (string, outcome) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {appID}, "client_secret": {string(secret)}, "scope": {teamsScope}}
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.teamsLoginBase()+"/"+url.PathEscape(tenant)+"/oauth2/v2.0/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", outcome{code: "bad_url", permanent: true}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)
	status, body, out := s.teamsDo(req)
	if !out.ok {
		if status == http.StatusUnauthorized || status == http.StatusBadRequest {
			out.gone, out.code = true, "teams_token_refused"
		}
		return "", out
	}
	var t struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(body, &t) != nil || len(t.AccessToken) < 16 || len(t.AccessToken) > 8192 || !teamsTokenPattern.MatchString(t.AccessToken) {
		return "", outcome{code: "teams_bad_answer", status: status}
	}
	return t.AccessToken, out
}

// teamsDo sends req, refusing redirects and reading up to 1 MiB.
func (s *Service) teamsDo(req *http.Request) (int, []byte, outcome) {
	resp, err := s.teamsClient().Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return 0, nil, outcome{code: "timeout"}
		}
		return 0, nil, outcome{code: "connection_failed"}
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, slackMaxAnswer))
	out := outcome{status: resp.StatusCode}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		out.code, out.retryAfter = "rate_limited", retryAfter(resp.Header.Get("Retry-After"))
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		out.code, out.permanent = "redirect_refused", true
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound:
		out.code, out.gone = "teams_"+strconv.Itoa(resp.StatusCode), true
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		out.code = "http_" + strconv.Itoa(resp.StatusCode)
	default:
		out.ok = true
	}
	return resp.StatusCode, body, out
}

// teamsConnector sends one Bot Connector request with token.
func (s *Service) teamsConnector(ctx context.Context, service, token, method, path string, body any) (int, []byte, outcome) {
	if !s.teamsServiceOK(service) {
		return 0, nil, outcome{code: "teams_service_refused", permanent: true}
	}
	if s.teamsService != "" {
		service = s.teamsService // the simulator (dev and tests)
	}
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	var r io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, outcome{code: "encode_failed", permanent: true}
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(service, "/")+path, r)
	if err != nil {
		return 0, nil, outcome{code: "bad_url", permanent: true}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", userAgent)
	return s.teamsDo(req)
}

// teamsMember is a member as the Bot Connector lists it.
type teamsMember struct {
	TenantID string `json:"tenantId"`
	UserRole string `json:"userRole"`
}

// checkTeams mints the bot's token and checks the channel's members.
func (s *Service) checkTeams(ctx context.Context, cfg dbq.GetTeamsAppChannelRow, secret []byte) error {
	token, out := s.teamsToken(ctx, cfg.TenantID.String(), cfg.AppID.String(), secret)
	switch {
	case out.ok:
	case out.gone || out.permanent:
		return ErrTeamsRefused
	default:
		return ErrTeamsUnavailable
	}
	return s.teamsMembers(ctx, cfg, token)
}

// teamsMembers reads every member of the channel (at most 20 pages of
// 500): the channel must exist with the bot in it, and every member must be
// of the channel's tenant and a user, never a guest. A channel that lists
// no one, or a member with no role, was not read (as teamsfacts).
func (s *Service) teamsMembers(ctx context.Context, cfg dbq.GetTeamsAppChannelRow, token string) error {
	cont, seen := "", 0
	for range 20 {
		q := url.Values{"pageSize": {"500"}}
		if cont != "" {
			q.Set("continuationToken", cont)
		}
		_, body, out := s.teamsConnector(ctx, cfg.ServiceUrl, token, http.MethodGet,
			"/v3/conversations/"+url.PathEscape(cfg.TeamsChannel)+"/pagedmembers?"+q.Encode(), nil)
		switch {
		case out.ok:
		case out.gone || out.permanent:
			return ErrTeamsChannel
		default:
			return ErrTeamsUnavailable
		}
		var page struct {
			Members           []teamsMember `json:"members"`
			ContinuationToken string        `json:"continuationToken"`
		}
		if json.Unmarshal(body, &page) != nil {
			return ErrTeamsUnavailable
		}
		for _, m := range page.Members {
			switch {
			case m.UserRole == "" || m.TenantID == "":
				return ErrTeamsUnread
			case !strings.EqualFold(m.TenantID, cfg.TenantID.String()) || m.UserRole != "user":
				return ErrTeamsShared
			}
		}
		seen += len(page.Members)
		if page.ContinuationToken == "" {
			if seen == 0 {
				return ErrTeamsUnread
			}
			return nil
		}
		cont = page.ContinuationToken
	}
	return ErrTeamsUnavailable // too many members to read: not shown internal
}

// ActivateTeamsApp activates a PENDING_ACTIVATION teams_app channel
// (HR-529): an Org Admin with a fresh step-up of their own key, the edition
// is Team or above, the bot's token is minted and the channel's members
// are all of its tenant and none a guest. A shared channel is recorded so
// and stays pending.
//
// permission: notification.manage
func (s *Service) ActivateTeamsApp(ctx context.Context, id ids.UUID, su stepup.StepUp) (ChannelView, error) {
	if err := s.requireSlackApprovals(ctx); err != nil {
		return ChannelView{}, err
	}
	var cfg dbq.GetTeamsAppChannelRow
	if err := s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, tx db.TenantTx) error {
		if !orgAdmin(c) {
			return ErrSlackOrgAdmin
		}
		if err := stepup.Check(ctx, tx, c, su, s.clock.Now()); err != nil {
			return err
		}
		var err error
		cfg, err = q.GetTeamsAppChannel(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotTeamsApp
		}
		return err
	}, db.ReadOnly()); err != nil {
		return ChannelView{}, err
	}
	if cfg.State != SlackPending {
		return ChannelView{}, ErrTeamsState
	}
	secret, err := s.envelope.Decrypt(ctx, s.field(cfg.OrgID, id, secretColumn), SecretPurpose, cfg.Secret)
	if err != nil {
		return ChannelView{}, err
	}
	checkErr := s.checkTeams(ctx, cfg, secret)
	if errors.Is(checkErr, ErrTeamsShared) {
		if err := s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, tx db.TenantTx) error {
			if _, err := q.MarkTeamsAppChannelShared(ctx, c.Org, id); err != nil {
				return err
			}
			return s.audit(ctx, tx, c, "notification.teams_app_refused_shared", id, nil)
		}); err != nil {
			return ChannelView{}, err
		}
	}
	if checkErr != nil {
		return ChannelView{}, checkErr
	}
	var out ChannelView
	err = s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := stepup.Check(ctx, tx, c, su, s.clock.Now()); err != nil {
			return err
		}
		n, err := q.ActivateTeamsAppChannel(ctx, dbq.ActivateTeamsAppChannelParams{
			ActivatedBy: &c.Principal.ID, ActivatedCredential: &su.Credential, OrgID: c.Org, ChannelRecordID: id, SeenUpdatedAt: cfg.UpdatedAt,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrTeamsState
		}
		row, err := q.GetChannel(ctx, c.Org, id)
		if err != nil {
			return err
		}
		out = channelView(row)
		return s.audit(ctx, tx, c, "notification.teams_app_activated", id, map[string]string{
			"teams_channel": cfg.TeamsChannel, "tenant": cfg.TenantID.String(), "security_key": su.Credential.String(),
		})
	})
	return out, err
}

// sendTeamsApp posts the link-only card of a new request to an ACTIVE
// teams_app channel, once per request (D256). Other notices post nothing.
func (s *Service) sendTeamsApp(ctx context.Context, org ids.OrgID, d dbq.LoadDeliveryRow, link string) outcome {
	if d.ChannelID == nil {
		return outcome{code: "no_channel", permanent: true}
	}
	if domain.CardEventOf(d.Type) != domain.CardPost {
		return outcome{skip: true, code: "not_a_card"}
	}
	if ok, err := s.slackApprovals(ctx); err != nil {
		return outcome{code: "edition_unavailable"}
	} else if !ok {
		return outcome{skip: true, code: "edition"}
	}
	request, isRequest := approvalRequestOf(d.LinkPath)
	if !isRequest {
		return outcome{skip: true, code: "no_card_subject"}
	}
	var cfg dbq.GetTeamsAppChannelRow
	var facts dbq.SlackCardFactsRow
	var stored *dbq.PcTeamsCard
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if cfg, err = q.GetTeamsAppChannel(ctx, org, *d.ChannelID); err != nil {
			return err
		}
		if facts, err = q.SlackCardFacts(ctx, org, request); err != nil {
			return err
		}
		c, err := q.GetTeamsCard(ctx, org, request, *d.ChannelID)
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
	case cfg.State != SlackActive || cfg.MembershipType == nil || *cfg.MembershipType != "internal":
		return outcome{skip: true, code: "channel_pending"}
	case domain.CardIsClosed(facts.State):
		return outcome{skip: true, code: "request_final"}
	case cfg.ActivatedAt == nil || facts.CreatedAt.Before(*cfg.ActivatedAt):
		return outcome{skip: true, code: "before_activation"}
	case stored != nil && stored.State == "POSTED":
		return outcome{skip: true, code: "card_sent"}
	case stored != nil:
		_ = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := dbq.New(tx).MarkTeamsCardUnknown(ctx, org, stored.CardID)
			return err
		})
		return outcome{code: "teams_post_unknown", permanent: true}
	}
	secret, err := s.openSecret(ctx, org, d, secretColumn, cfg.Secret)
	if err != nil {
		return outcome{code: "secret_unavailable"}
	}
	token, out := s.teamsToken(ctx, cfg.TenantID.String(), cfg.AppID.String(), secret)
	if !out.ok {
		return out
	}
	// The channel may have changed since activation: read it before each
	// card, and send nothing unless it is still internal (D277).
	switch err := s.teamsMembers(ctx, cfg, token); {
	case err == nil:
	case errors.Is(err, ErrTeamsShared):
		if err := s.pauseSharedTeams(ctx, org, cfg); err != nil {
			return outcome{code: "store_failed"}
		}
		return outcome{skip: true, code: "channel_shared"}
	case errors.Is(err, ErrTeamsChannel):
		return outcome{code: "teams_channel_refused", permanent: true}
	case errors.Is(err, ErrTeamsUnread):
		return outcome{code: "teams_channel_unread"}
	default:
		return outcome{code: "teams_unavailable"}
	}
	cardID := ids.NewV7()
	var claimed int64
	if err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		claimed, err = dbq.New(tx).ClaimTeamsCard(ctx, dbq.ClaimTeamsCardParams{OrgID: org, CardID: cardID, RequestID: request, ChannelRecordID: *d.ChannelID})
		return err
	}); err != nil {
		return outcome{code: "store_failed"}
	}
	if claimed == 0 {
		return outcome{skip: true, code: "card_claimed"}
	}
	f := domain.CardFacts{
		Level: domain.SlackMinimal, Kind: facts.SubjectKind, Consequence: facts.Reversibility, State: facts.State,
		ExpiresAt: facts.DeadlineAt, RequestID: request.String(), Link: link, Simulated: strings.HasPrefix(d.Title, domain.SimulatedPrefix),
	}
	status, body, out := s.teamsConnector(ctx, cfg.ServiceUrl, token, http.MethodPost,
		"/v3/conversations/"+url.PathEscape(cfg.TeamsChannel)+"/activities", domain.TeamsOpenCard(f))
	var posted struct {
		ID string `json:"id"`
	}
	if !out.ok || json.Unmarshal(body, &posted) != nil || posted.ID == "" || len(posted.ID) > 256 {
		refused := out.status >= 400 && out.status < 500 || out.code == "teams_service_refused"
		_ = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			q := dbq.New(tx)
			if refused {
				_, err := q.ReleaseTeamsCard(ctx, org, cardID)
				return err
			}
			_, err := q.MarkTeamsCardUnknown(ctx, org, cardID)
			return err
		})
		if !out.ok {
			return out
		}
		return outcome{code: "teams_post_unknown", status: status, permanent: true}
	}
	var serr error
	for range 3 { // the post is done: storing it is retried, never the post
		if serr = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := dbq.New(tx).SetTeamsCardPosted(ctx, &posted.ID, org, cardID)
			return err
		}); serr == nil {
			break
		}
	}
	if serr != nil {
		s.log.WarnContext(ctx, "notifications.teams_card_not_stored", slog.String("card", cardID.String()), pclog.Err(serr))
		return outcome{code: "store_failed"}
	}
	return out
}

// pauseSharedTeams returns an active channel found shared to
// PENDING_ACTIVATION, audited, and tells the org's admins.
func (s *Service) pauseSharedTeams(ctx context.Context, org ids.OrgID, cfg dbq.GetTeamsAppChannelRow) error {
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.PauseSharedTeamsAppChannel(ctx, org, cfg.ChannelRecordID)
		if err != nil || n == 0 {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "notification.teams_channel_shared", Actor: evdomain.Actor{Type: "system", ID: "notification-health"},
			Outcome: audit.Success, ReasonCode: "TEAMS_CHANNEL_SHARED",
			Object:  &audit.Object{Type: "notification_channel", ID: cfg.ChannelRecordID.String()},
			Details: map[string]string{"teams_channel": cfg.TeamsChannel},
		}); err != nil {
			return err
		}
		admins, err := q.OrgUsersWithRoles(ctx, org, []string{string(td.RoleOrgAdmin)})
		if err != nil {
			return err
		}
		_, err = s.Enqueue(ctx, tx, Message{
			Org: org, Type: "notification.teams_channel_shared", Params: map[string]string{"channel": cfg.ChannelName},
			Personal: admins, Subject: &Subject{Type: "notification_channel", ID: cfg.ChannelRecordID},
			DedupeKey: "teams-shared:" + cfg.ChannelRecordID.String() + ":" + fmt.Sprint(s.clock.Now().Unix()),
		})
		return err
	})
}

// TeamsAppView is a teams_app channel's configuration, without its secret.
type TeamsAppView struct {
	TenantID, TeamID, ChannelID, AppID, ServiceURL, State string
	ActivatedAt, SharedAt                                 *time.Time
}

// TeamsConfirmPath is a teams_app channel's activation page.
func TeamsConfirmPath(id ids.UUID) string {
	return "/notifications/channels/" + id.String() + "/confirm-teams"
}

// withTeamsApp adds a teams_app channel's configuration to its view.
func (s *Service) withTeamsApp(ctx context.Context, q *dbq.Queries, org ids.OrgID, v ChannelView) (ChannelView, error) {
	if v.Kind != domain.KindTeamsApp {
		return v, nil
	}
	a, err := q.GetTeamsAppChannel(ctx, org, v.ID)
	if db.IsNoRows(err) {
		return v, nil
	} else if err != nil {
		return v, err
	}
	v.TeamsApp = &TeamsAppView{
		TenantID: a.TenantID.String(), TeamID: a.TeamID, ChannelID: a.TeamsChannel, AppID: a.AppID.String(), ServiceURL: a.ServiceUrl,
		State: a.State, ActivatedAt: a.ActivatedAt, SharedAt: a.SharedAt,
	}
	return v, nil
}

// insertTeamsApp stores a new teams_app channel's configuration,
// PENDING_ACTIVATION.
func (s *Service) insertTeamsApp(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID, c domain.TeamsAppConfig) error {
	tenant, err := ids.ParseUUID(c.TenantID)
	if err != nil {
		return domain.ErrInvalid
	}
	app, err := ids.ParseUUID(c.AppID)
	if err != nil {
		return domain.ErrInvalid
	}
	if !s.teamsServiceOK(c.ServiceURL) {
		return domain.ErrInvalid
	}
	return dbq.New(tx).InsertTeamsAppChannel(ctx, dbq.InsertTeamsAppChannelParams{
		OrgID: org, ChannelRecordID: id, TenantID: tenant, TeamID: c.TeamID, TeamsChannel: c.ChannelID, AppID: app, ServiceUrl: c.ServiceURL,
	})
}
