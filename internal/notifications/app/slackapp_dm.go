// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Slack approval DMs (G0 M20 D256; HR-313, HR-314, HR-529, T-228). An
// approval notice the waitlist router sends to the eligible deciders it
// computed (at most 50) also goes, as a direct message, to each of them
// whose Slack identity is linked and confirmed. The DM is the minimal card
// and its link to the approval page; it has no interactive element and
// decides nothing. When it is sent, the recipient must still be recorded
// as a decider of the request by the router, the link must still be
// confirmed in the workspace of the org's DM channel, and the request must
// still wait: otherwise nothing is sent. A DM is posted at most once per
// request and person.
//
// A person's link comes from Slack's users.lookupByEmail with the bot
// token, for the email PantherClaw has for them, and is used only once
// they confirm it in the console; either side may revoke it.

// Chat identity link states (migration 00244).
const (
	LinkProposed  = "PROPOSED"
	LinkConfirmed = "CONFIRMED"
	LinkStale     = "STALE"
	LinkRevoked   = "REVOKED"
)

// Slack DM claim states (migration 00244).
const (
	dmPosting = "POSTING"
	dmPosted  = "POSTED"
	dmUnknown = "UNKNOWN"
)

var (
	slackUserPattern = regexp.MustCompile(`^[UW][A-Z0-9]{4,30}$`)
	slackIMPattern   = regexp.MustCompile(`^D[A-Z0-9]{8,12}$`)
)

// Chat link errors.
var (
	ErrNoDMChannel = pcerr.New(pcerr.FailedPrecondition, "SLACK_DM_UNAVAILABLE",
		"no active Slack app channel of this organization sends direct messages")
	ErrSlackLinkNotFound = pcerr.New(pcerr.NotFound, "CHAT_LINK_NOT_FOUND", "chat identity link not found")
	ErrSlackLinkRefused  = pcerr.New(pcerr.FailedPrecondition, "CHAT_LINK_REFUSED",
		"Slack has no full member of the workspace with this person's confirmed email")
	ErrSlackLinkState = pcerr.New(pcerr.FailedPrecondition, "CHAT_LINK_STATE", "the chat identity link is not in a state that allows this")
	ErrLinkHumanOnly  = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person links their own chat identity")
)

// ChatLink is a person's chat identity link.
type ChatLink struct {
	ID, User                              ids.UUID
	Provider, TeamID, ExternalUser, Email string
	State                                 string
	Created                               time.Time
	ConfirmedAt, RevokedAt                *time.Time
}

func chatLinkOf(r dbq.PcChatIdentityLink) ChatLink {
	return ChatLink{
		ID: r.ID, User: r.UserID, Provider: r.Provider, TeamID: r.TeamID, ExternalUser: r.ExternalUserID, Email: r.Email,
		State: r.State, Created: r.CreatedAt, ConfirmedAt: r.ConfirmedAt, RevokedAt: r.RevokedAt,
	}
}

// self returns the caller when it is a person signed in to the console (not
// an API key or a service account).
func self(ctx context.Context) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.Human() || c.Credential == tapp.CredAPIKey {
		return c, ErrLinkHumanOnly
	}
	return c, nil
}

// slackUser is the part of a users.lookupByEmail answer the link reads.
type slackUser struct {
	User struct {
		ID                string `json:"id"`
		TeamID            string `json:"team_id"`
		Deleted           bool   `json:"deleted"`
		IsBot             bool   `json:"is_bot"`
		IsRestricted      bool   `json:"is_restricted"`
		IsUltraRestricted bool   `json:"is_ultra_restricted"`
		IsEmailConfirmed  bool   `json:"is_email_confirmed"`
		Profile           struct {
			Email string `json:"email"`
		} `json:"profile"`
	} `json:"user"`
}

// ProposeSlackLink looks the caller up in the workspace of the org's DM
// channel by the email PantherClaw has for them and proposes the link. It
// is used only once the caller confirms it (ConfirmChatLink).
//
// permission: authenticated (a person links their own identity)
func (s *Service) ProposeSlackLink(ctx context.Context) (ChatLink, error) {
	c, err := self(ctx)
	if err != nil {
		return ChatLink{}, err
	}
	if err := s.requireSlackApprovals(ctx); err != nil {
		return ChatLink{}, err
	}
	var ch dbq.SlackDMChannelRow
	var email string
	if err := s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if ch, err = q.SlackDMChannel(ctx, c.Org); db.IsNoRows(err) {
			return ErrNoDMChannel
		} else if err != nil {
			return err
		}
		email, err = q.UserEmail(ctx, c.Org, c.Principal.ID)
		return err
	}, db.ReadOnly()); err != nil {
		return ChatLink{}, err
	}
	email = strings.TrimSpace(email)
	if email == "" || ch.TeamID == nil || len(email) > 320 {
		return ChatLink{}, ErrSlackLinkRefused
	}
	token, err := s.envelope.Decrypt(ctx, s.field(c.Org, ch.ChannelRecordID, secretColumn), SecretPurpose, ch.Secret)
	if err != nil {
		return ChatLink{}, err
	}
	u, err := s.slackMember(ctx, string(token), *ch.TeamID, email, ch.AllowedEmailDomains)
	if err != nil {
		return ChatLink{}, err
	}
	var link ChatLink
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).InsertChatIdentityLink(ctx, dbq.InsertChatIdentityLinkParams{
			OrgID: c.Org, ID: ids.NewV7(), UserID: c.Principal.ID, Provider: "slack", TeamID: *ch.TeamID,
			ExternalUserID: u, Email: email, ProposedBy: c.Principal.String(),
		})
		if db.IsUniqueViolation(err) {
			return ErrSlackLinkState // a live link exists for the person or the Slack user
		} else if err != nil {
			return err
		}
		link = chatLinkOf(row)
		return s.linkAudit(ctx, tx, c, "notification.chat_link_proposed", row)
	})
	return link, err
}

// ConfirmChatLink confirms the caller's own PROPOSED link: from now on
// approval DMs for requests they may decide reach them in Slack.
//
// permission: authenticated (a person confirms their own link)
func (s *Service) ConfirmChatLink(ctx context.Context, id ids.UUID) (ChatLink, error) {
	return s.moveLink(ctx, id, LinkProposed, LinkConfirmed, "notification.chat_link_confirmed")
}

// RevokeChatLink revokes the caller's own link, proposed or confirmed.
//
// permission: authenticated (a person revokes their own link)
func (s *Service) RevokeChatLink(ctx context.Context, id ids.UUID) (ChatLink, error) {
	link, err := s.moveLink(ctx, id, LinkConfirmed, LinkRevoked, "notification.chat_link_revoked")
	if errors.Is(err, ErrSlackLinkState) {
		return s.moveLink(ctx, id, LinkProposed, LinkRevoked, "notification.chat_link_revoked")
	}
	return link, err
}

func (s *Service) moveLink(ctx context.Context, id ids.UUID, from, to, event string) (ChatLink, error) {
	c, err := self(ctx)
	if err != nil {
		return ChatLink{}, err
	}
	var out ChatLink
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.GetChatIdentityLink(ctx, c.Org, id)
		if db.IsNoRows(err) || (err == nil && row.UserID != c.Principal.ID) {
			return ErrSlackLinkNotFound // another person's link looks like none
		} else if err != nil {
			return err
		}
		n, err := q.SetChatIdentityLinkState(ctx, dbq.SetChatIdentityLinkStateParams{
			State: to, OrgID: c.Org, ID: id, UserID: c.Principal.ID, FromState: from,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrSlackLinkState
		}
		if row, err = q.GetChatIdentityLink(ctx, c.Org, id); err != nil {
			return err
		}
		out = chatLinkOf(row)
		return s.linkAudit(ctx, tx, c, event, row)
	})
	return out, err
}

// ChatLinks lists the caller's own links, newest first.
//
// permission: authenticated (a person reads their own links)
func (s *Service) ChatLinks(ctx context.Context) ([]ChatLink, error) {
	c, err := self(ctx)
	if err != nil {
		return nil, err
	}
	var out []ChatLink
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).UserChatIdentityLinks(ctx, c.Org, c.Principal.ID)
		for _, r := range rows {
			out = append(out, chatLinkOf(r))
		}
		return err
	}, db.ReadOnly())
	return out, err
}

func (s *Service) linkAudit(ctx context.Context, tx db.TenantTx, c tapp.Caller, event string, l dbq.PcChatIdentityLink) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: event, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "chat_identity_link", ID: l.ID.String()},
		Details: map[string]string{"provider": l.Provider, "team": l.TeamID, "slack_user": l.ExternalUserID},
	})
	return err
}

// dmRecipients returns the delivery a decider notice adds for each of
// users with a confirmed Slack link: the DM channel and the users. Nothing
// when the org has no active DM channel.
func dmRecipients(ctx context.Context, q *dbq.Queries, org ids.OrgID, users []ids.UUID) (ids.UUID, []ids.UUID, error) {
	ch, err := q.SlackDMChannel(ctx, org)
	if db.IsNoRows(err) || (err == nil && ch.TeamID == nil) {
		return ids.UUID{}, nil, nil
	} else if err != nil {
		return ids.UUID{}, nil, err
	}
	links, err := q.ConfirmedSlackLinks(ctx, org, *ch.TeamID, users)
	if err != nil {
		return ids.UUID{}, nil, err
	}
	out := make([]ids.UUID, 0, len(links))
	for _, l := range links {
		out = append(out, l.UserID)
	}
	return ch.ChannelRecordID, out, nil
}

// sendSlackDM delivers one approval DM (HR-529). Every condition is read
// again at send time; a DM that may no longer be sent is skipped.
func (s *Service) sendSlackDM(ctx context.Context, org ids.OrgID, d dbq.LoadDeliveryRow, link string) outcome {
	if d.ChannelID == nil || d.RecipientUserID == nil {
		return outcome{code: "no_recipient", permanent: true}
	}
	if !domain.DMEvent(d.Type) {
		return outcome{skip: true, code: "not_a_dm"}
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
	user := *d.RecipientUserID
	var ch dbq.SlackDMChannelRow
	var target string
	var chat dbq.ConfirmedSlackLinksRow
	var facts dbq.SlackCardFactsRow
	var stored *dbq.PcSlackDirectMessage
	skip := ""
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if ch, err = q.SlackDMChannel(ctx, org); db.IsNoRows(err) {
			skip = "no_dm_channel"
			return nil
		} else if err != nil {
			return err
		}
		if ch.ChannelRecordID != *d.ChannelID || ch.TeamID == nil {
			skip = "dm_channel_changed"
			return nil
		}
		// Only a decider the router recorded for this request (HR-529).
		if routed, err := q.RoutedDecider(ctx, org, &user, request); err != nil {
			return err
		} else if !routed {
			skip = "not_a_decider"
			return nil
		}
		links, err := q.ConfirmedSlackLinks(ctx, org, *ch.TeamID, []ids.UUID{user})
		if err != nil {
			return err
		}
		if len(links) != 1 {
			skip = "not_linked"
			return nil
		}
		chat, target = links[0], links[0].ExternalUserID
		if facts, err = q.SlackCardFacts(ctx, org, request); db.IsNoRows(err) {
			skip = "no_card_subject"
			return nil
		} else if err != nil {
			return err
		}
		dm, err := q.GetSlackDM(ctx, org, request, user)
		if err == nil {
			stored = &dm
		} else if !db.IsNoRows(err) {
			return err
		}
		return nil
	}, db.ReadOnly())
	switch {
	case err != nil:
		return outcome{code: "load_failed"}
	case skip != "":
		return outcome{skip: true, code: skip}
	case domain.CardIsClosed(facts.State):
		return outcome{skip: true, code: "request_final"}
	case ch.ActivatedAt == nil || facts.CreatedAt.Before(*ch.ActivatedAt):
		return outcome{skip: true, code: "before_activation"}
	}
	if stored != nil {
		switch stored.State {
		case dmPosting:
			_ = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
				_, err := dbq.New(tx).MarkSlackDMUnknown(ctx, org, stored.ID)
				return err
			})
			return outcome{code: "slack_post_unknown", permanent: true}
		case dmUnknown:
			return outcome{code: "slack_post_unknown", permanent: true}
		}
		return outcome{skip: true, code: "dm_sent"}
	}
	token, err := s.envelope.Decrypt(ctx, s.field(org, ch.ChannelRecordID, secretColumn), SecretPurpose, ch.Secret)
	if err != nil {
		return outcome{code: "secret_unavailable"}
	}
	// Slack must still answer the link's email with the same full member,
	// on an allowed domain (D265); otherwise the link is stale and no DM goes.
	switch now, err := s.slackMember(ctx, string(token), *ch.TeamID, chat.Email, ch.AllowedEmailDomains); {
	case errors.Is(err, ErrSlackUnavailable):
		return outcome{code: "slack_unavailable"}
	case err != nil || now != target:
		if err := s.staleLink(ctx, org, chat); err != nil {
			return outcome{code: "store_failed"}
		}
		return outcome{skip: true, code: "link_stale"}
	}
	dmID := ids.NewV7()
	var claimed int64
	if err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		claimed, err = dbq.New(tx).ClaimSlackDM(ctx, dbq.ClaimSlackDMParams{
			OrgID: org, ID: dmID, RequestID: request, UserID: user, ChannelRecordID: ch.ChannelRecordID,
		})
		return err
	}); err != nil {
		return outcome{code: "store_failed"}
	}
	if claimed == 0 {
		return outcome{skip: true, code: "dm_claimed"} // another delivery posts it
	}
	release := func(out outcome) outcome {
		_ = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := dbq.New(tx).ReleaseSlackDM(ctx, org, dmID)
			return err
		})
		return out
	}
	a, out := s.slackCall(ctx, string(token), "conversations.open", map[string]any{"users": target}, nil)
	var im struct {
		ID string `json:"id"`
	}
	if !out.ok {
		return release(out) // opening a DM posts nothing
	}
	if json.Unmarshal(a.Channel, &im) != nil || !slackIMPattern.MatchString(im.ID) {
		return release(outcome{code: "slack_bad_answer", status: out.status})
	}
	// The minimal card: fixed labels, ids and times, and the link (HR-314).
	f := domain.CardFacts{
		Level: domain.SlackMinimal, Kind: facts.SubjectKind, Consequence: facts.Reversibility, State: facts.State,
		ExpiresAt: facts.DeadlineAt, RequestID: request.String(), Link: link,
		Simulated: strings.HasPrefix(d.Title, domain.SimulatedPrefix),
	}
	ts, out := s.slackPost(ctx, string(token), im.ID, "", domain.OpenCard(f))
	if !out.ok {
		if slackRefused(out) {
			return release(out)
		}
		_ = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := dbq.New(tx).MarkSlackDMUnknown(ctx, org, dmID)
			return err
		})
		return outcome{code: "slack_post_unknown", status: out.status, permanent: true}
	}
	var serr error
	for range 3 { // the post is done: storing it is retried, never the post
		if serr = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := dbq.New(tx).SetSlackDMPosted(ctx, dbq.SetSlackDMPostedParams{ImChannel: &im.ID, Ts: &ts, OrgID: org, ID: dmID})
			return err
		}); serr == nil {
			break
		}
	}
	if serr != nil {
		return outcome{code: "store_failed"} // the retry finds the claim and marks it UNKNOWN
	}
	return out
}

// dmRecipientsFor adds the DM deliveries of a decider notice (HR-529): the
// personal recipients of a notice the waitlist router marked as going to
// eligible deciders, who have a confirmed link.
func (s *Service) dmRecipientsFor(ctx context.Context, tx db.TenantTx, q *dbq.Queries, m Message, note ids.UUID) (int, error) {
	if !m.Deciders || len(m.Personal) == 0 || !domain.DMEvent(m.Type) {
		return 0, nil
	}
	channel, users, err := dmRecipients(ctx, q, m.Org, m.Personal)
	if err != nil || len(users) == 0 {
		return 0, err
	}
	for _, u := range users {
		if err := s.addDelivery(ctx, tx, q, m.Org, note, &channel, &u, domain.KindSlackDM, "PENDING"); err != nil {
			return 0, err
		}
	}
	return len(users), nil
}

// maxEmailDomains bounds a DM channel's email domains (D265).
const maxEmailDomains = 20

var emailDomainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// checkEmailDomains refuses a slack_app configuration whose email domains
// do not fit its DM setting: 1 to 20 distinct lowercase exact domains for
// a DM channel, none otherwise (D265).
func checkEmailDomains(c *domain.SlackAppConfig) error {
	if !c.DirectMessages {
		if len(c.AllowedEmailDomains) > 0 {
			return domain.ErrInvalid
		}
		return nil
	}
	if len(c.AllowedEmailDomains) < 1 || len(c.AllowedEmailDomains) > maxEmailDomains {
		return domain.ErrInvalid
	}
	seen := map[string]bool{}
	for _, d := range c.AllowedEmailDomains {
		if len(d) > 253 || !emailDomainPattern.MatchString(d) || seen[d] {
			return domain.ErrInvalid
		}
		seen[d] = true
	}
	return nil
}

// emailAllowed reports whether email's domain is exactly one of domains.
func emailAllowed(email string, domains []string) bool {
	at := strings.LastIndexByte(email, '@')
	if at < 1 || at == len(email)-1 {
		return false
	}
	d := strings.ToLower(email[at+1:])
	for _, x := range domains {
		if d == x {
			return true
		}
	}
	return false
}

func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// slackMember asks Slack who has email and returns their user id when
// that is a full member of team (not a guest, a bot or deleted) whose
// confirmed email is exactly email, on one of domains (D256, D265).
// ErrSlackLinkRefused when not; ErrSlackUnavailable when Slack could not
// answer.
func (s *Service) slackMember(ctx context.Context, token, team, email string, domains []string) (string, error) {
	if !emailAllowed(email, domains) {
		return "", ErrSlackLinkRefused
	}
	a, out := s.slackCall(ctx, token, "users.lookupByEmail", nil, map[string][]string{"email": {email}})
	switch {
	case out.ok:
	case out.gone || out.permanent:
		return "", ErrSlackLinkRefused
	default:
		return "", ErrSlackUnavailable
	}
	var u slackUser
	if err := json.Unmarshal(a.body, &u); err != nil {
		return "", ErrSlackLinkRefused
	}
	switch {
	case !slackUserPattern.MatchString(u.User.ID), u.User.TeamID != team, u.User.Deleted, u.User.IsBot,
		u.User.IsRestricted, u.User.IsUltraRestricted, !u.User.IsEmailConfirmed,
		!strings.EqualFold(strings.TrimSpace(u.User.Profile.Email), email):
		return "", ErrSlackLinkRefused
	}
	return u.User.ID, nil
}

// staleLink marks a confirmed link STALE and audits it (D265).
func (s *Service) staleLink(ctx context.Context, org ids.OrgID, l dbq.ConfirmedSlackLinksRow) error {
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		n, err := dbq.New(tx).MarkChatIdentityLinkStale(ctx, org, l.ID)
		if err != nil || n == 0 {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "notification.chat_link_stale", Actor: evdomain.Actor{Type: "system", ID: "notification-health"},
			Outcome: audit.Success, ReasonCode: "SLACK_MEMBER_CHANGED", Object: &audit.Object{Type: "chat_identity_link", ID: l.ID.String()},
			Details: map[string]string{"provider": "slack", "slack_user": l.ExternalUserID, "user": l.UserID.String()},
		})
		return err
	})
}
