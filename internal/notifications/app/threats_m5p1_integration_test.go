// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	billingdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/notifications/adapters/smtpmail"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/notifications/smtptest"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// p1tRouteAll sends every destination to the test receiver, whatever its
// host, skipping certificate checks (as TestHR158_SlackGetsEscapedTextAndOneLink
// does to stand in for hooks.slack.com).
func p1tRouteAll(r *receiver) *http.Client {
	addr := r.Listener.Addr().String()
	return &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
	}
}

// p1tResolver is the production egress client behind a resolver that
// answers each name with answers[name] at dial time, as a rebinding DNS
// server or a resolver accepting inet_aton spellings would. No other name
// is looked up.
func p1tResolver(t *testing.T, answers map[string]string) *http.Client {
	t.Helper()
	c := httpx.NewEgressClient(httpx.EgressConfig{Timeout: 5 * time.Second})
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("egress transport %T", c.Transport)
	}
	tr = tr.Clone()
	dial := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		to, ok := answers[host]
		if err != nil || !ok {
			return nil, fmt.Errorf("p1t: no answer for %q", addr)
		}
		return dial(ctx, network, to)
	}
	c.Transport = tr
	return c
}

// p1tLogged is e's service again, logging to log.
func p1tLogged(t *testing.T, e *env, log *slog.Logger) *napp.Service {
	t.Helper()
	jc, err := jobs.NewClient(e.pool, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := napp.New(e.pool, jc, e.envelope, napp.Config{PublicURL: "https://pc.example.test"}, clock.System{}, log)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// p1tIDs runs a query returning delivery ids in e's org.
func p1tIDs(t *testing.T, e *env, sql string, args ...any) []ids.UUID {
	t.Helper()
	var out []ids.UUID
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id ids.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// p1tDeliverAll makes one attempt of every pending delivery, as the
// workers would; failed attempts stay pending for a retry.
func p1tDeliverAll(t *testing.T, e *env) {
	t.Helper()
	for _, id := range p1tIDs(t, e, "SELECT id FROM pc.deliveries WHERE state = 'PENDING' ORDER BY created_at, id") {
		_ = e.svc.Deliver(context.Background(), e.org, id)
	}
}

// p1tSecurityNotice files a security notice as authn does.
func p1tSecurityNotice(t *testing.T, e *env, n authnapp.SecurityNotice) {
	t.Helper()
	n.Org = e.org
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return e.svc.SecurityNotice(ctx, tx, n)
	}); err != nil {
		t.Fatal(err)
	}
}

// TestT053_ChannelsNeverReachInternalAddresses: T-053 — a tenant admin
// aims channels, through the channel API, at cloud metadata in its
// spellings, at loopback and private ranges, at PantherClaw itself, and at
// names that resolve to such addresses only at dial time (DNS rebinding,
// inet_aton spellings, metadata host names). Each is refused when saved or,
// if saved, its test notification is denied at dial time: nothing reaches
// the target. An operator's private range never re-allows metadata.
// TestHR157_* and TestHR159_RedirectsRateLimitsAndGoneEndpoints (redirects)
// cover each check alone.
func TestT053_ChannelsNeverReachInternalAddresses(t *testing.T) {
	t.Run("refused when saved", func(t *testing.T) {
		e := newEnv(t)
		e.svc.SetEditions(edition(billingdomain.Team))
		admin := e.as(td.KindUser, e.alice, td.RoleOrgAdmin)
		var bad []napp.ChannelInput
		for _, u := range []string{
			"https://169.254.169.254/latest/meta-data/iam/security-credentials/",
			"https://[::ffff:169.254.169.254]/latest/meta-data/",
			"https://[::ffff:a9fe:a9fe]/latest/meta-data/",
			"https://[64:ff9b::a9fe:a9fe]/latest/meta-data/",
			"https://[fd00:ec2::254]/latest/meta-data/",
			"https://100.100.100.200/latest/meta-data/",
			"https://168.63.129.16/machine?comp=goalstate",
			"https://127.0.0.1:8443/hook", "https://[::1]/hook", "https://localhost/hook", "https://admin.localhost/hook",
			"https://0.0.0.0/hook", "https://[::]/hook", "https://10.0.0.1/hook", "https://172.16.0.1/hook",
			"https://192.168.0.1/hook", "https://100.64.0.1/hook", "https://[fe80::1]/hook",
			"https://pc.example.test/v1/approvals", "https://PC.Example.Test./hook", "https://pc.example.test:8443/hook",
			"https://hooks.example.com@169.254.169.254/latest/", "http://hooks.example.com/hook",
		} {
			bad = append(bad, napp.ChannelInput{Kind: domain.KindWebhook, URL: u})
		}
		for _, u := range []string{
			"https://169.254.169.254/services/T0/B0/X",
			"https://hooks.slack.com@169.254.169.254/services/T0/B0/X",
			"https://hooks.slack.com.evil.example/services/T0/B0/X",
			"https://pc.example.test/services/T0/B0/X",
		} {
			bad = append(bad, napp.ChannelInput{Kind: domain.KindSlack, URL: u})
		}
		for i, in := range bad {
			in.Name, in.EventTypes = fmt.Sprintf("probe-%d", i), []string{"security.*"}
			if _, _, err := e.svc.CreateChannel(admin, in); !errors.Is(err, napp.ErrInvalidURL) {
				t.Errorf("%s channel to %s: %v, want ErrInvalidURL", in.Kind, in.URL, err)
			}
		}
		if n := e.count(t, "SELECT count(*) FROM pc.notification_channels"); n != 0 {
			t.Fatalf("%d channels stored", n)
		}

		// A self-hosted operator opens private ranges; metadata stays shut.
		op := newEnvConfig(t, napp.Config{PublicURL: "https://pc.example.test", AllowedPrivateRanges: []netip.Prefix{
			netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd00::/8"),
		}})
		opAdmin := op.as(td.KindUser, op.alice, td.RoleOrgAdmin)
		hook := func(name, u string) napp.ChannelInput {
			return napp.ChannelInput{Name: name, Kind: domain.KindWebhook, EventTypes: []string{"security.*"}, URL: u}
		}
		if _, _, err := op.svc.CreateChannel(opAdmin, hook("on-prem", "https://169.254.10.10/hook")); err != nil {
			t.Fatalf("a private address inside the operator's range: %v", err)
		}
		for i, u := range []string{
			"https://169.254.169.254/latest/", "https://[fd00:ec2::254]/latest/", "https://100.100.100.200/latest/",
			"https://[::ffff:169.254.169.254]/latest/",
		} {
			if _, _, err := op.svc.CreateChannel(opAdmin, hook(fmt.Sprintf("metadata-%d", i), u)); !errors.Is(err, napp.ErrInvalidURL) {
				t.Errorf("metadata %s inside the operator's range: %v", u, err)
			}
		}
	})

	t.Run("denied at dial time", func(t *testing.T) {
		r := newReceiver(t)
		e := newEnv(t)
		e.svc.SetEditions(edition(billingdomain.Team))
		admin := e.as(td.KindUser, e.alice, td.RoleOrgAdmin)
		_, port, _ := net.SplitHostPort(r.Listener.Addr().String())
		answers := map[string]string{
			"hooks.example.com":        net.JoinHostPort("127.0.0.1", port), // rebinds to the receiver on loopback
			"rebind.example.net":       "[fd00:ec2::254]:443",
			"2852039166":               "169.254.169.254:443",
			"0xa9fea9fe":               "169.254.169.254:443",
			"0251.0376.0251.0376":      "169.254.169.254:443",
			"metadata.google.internal": "169.254.169.254:443",
		}
		e.svc.SetHTTPClient(p1tResolver(t, answers))
		ctx := context.Background()
		i := 0
		for host := range answers {
			i++
			ch, _, err := e.svc.CreateChannel(admin, napp.ChannelInput{
				Name: fmt.Sprintf("probe-%d", i), Kind: domain.KindWebhook, EventTypes: []string{"security.*"},
				URL: "https://" + host + "/latest/meta-data/",
			})
			if errors.Is(err, napp.ErrInvalidURL) {
				continue // refused when saved: as good
			}
			if err != nil {
				t.Fatalf("%s: %v", host, err)
			}
			note, err := e.svc.TestChannel(admin, ch.ID)
			if err != nil {
				t.Fatal(err)
			}
			ds := p1tIDs(t, e, "SELECT id FROM pc.deliveries WHERE notification_id = $1", note)
			if len(ds) != 1 {
				t.Fatalf("%s: %d test deliveries", host, len(ds))
			}
			if err := e.svc.Deliver(ctx, e.org, ds[0]); err == nil {
				t.Errorf("%s: a denied destination counts as delivered", host)
			}
			if row := e.row(t, ds[0]); row.state != "PENDING" || row.lastError != "destination_denied" || row.status != nil {
				t.Errorf("%s: delivery %+v, want denied at dial time", host, row)
			}
		}
		if n := len(r.got()); n != 0 {
			t.Fatalf("%d requests reached the internal receiver", n)
		}
	})
}

// TestT053_ChannelSecretsAndMailStayContained: T-053 — a channel's
// secrets (the Slack URL, the webhook signing secret) are shown at most
// once and never come back through the API, the log, the audit trail or a
// delivery error, and a sealed secret moved to another channel's row sends
// nothing. Mail goes only to org members' addresses: an email channel
// cannot name an address, and an address carrying a header injection is
// refused before any mail is sent. TestHR157_ChannelsValidateAndEncryptTheirSecrets
// and TestHR157_MailRefusesPlaintextAndInjection cover the pieces.
func TestT053_ChannelSecretsAndMailStayContained(t *testing.T) {
	t.Run("secrets", func(t *testing.T) {
		r := newReceiver(t, status(http.StatusInternalServerError), status(http.StatusInternalServerError))
		e := newEnv(t)
		var logs bytes.Buffer
		e.svc = p1tLogged(t, e, slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
		e.svc.SetHTTPClient(p1tRouteAll(r))
		admin := e.as(td.KindUser, e.alice, td.RoleOrgAdmin)
		const slackToken = "T0SECRET/B0SECRET/XSECRETTOKEN"
		hook, hookSecret, err := e.svc.CreateChannel(admin, napp.ChannelInput{
			Name: "siem", Kind: domain.KindWebhook, EventTypes: []string{"security.*"}, URL: "https://hooks.example.com/pc",
		})
		if err != nil {
			t.Fatal(err)
		}
		slack, shown, err := e.svc.CreateChannel(admin, napp.ChannelInput{
			Name: "chat", Kind: domain.KindSlack, EventTypes: []string{"security.*"}, URL: "https://hooks.slack.com/services/" + slackToken,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := e.svc.CreateChannel(admin, logChannel("ops-log")); err != nil {
			t.Fatal(err)
		}
		if hookSecret == "" || shown != "" {
			t.Fatalf("shown at creation: webhook secret %t, Slack %q", hookSecret != "", shown)
		}
		views, _, err := e.svc.ListChannels(admin, firstPage())
		if err != nil || len(views) != 3 {
			t.Fatalf("list: %d %v", len(views), err)
		}
		got, _, err := e.svc.GetChannel(admin, slack.ID)
		if err != nil || got.URL != "" {
			t.Fatalf("get Slack channel: URL %q, %v", got.URL, err)
		}
		for _, v := range views {
			if strings.Contains(v.URL, "SECRET") {
				t.Errorf("channel %s lists its Slack URL", v.Name)
			}
		}

		e.enqueue(t, napp.Message{Type: "security.credential_registered", Params: registered("alice@example.test")})
		p1tDeliverAll(t, e)
		if n := len(r.got()); n != 2 {
			t.Fatalf("%d requests, want the Slack and webhook attempts", n)
		}
		if !strings.Contains(logs.String(), "notification.delivered") || e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE position('siem'::bytea IN body) > 0") == 0 {
			t.Fatal("nothing to search: the log channel did not log or the creation was not audited")
		}
		for _, s := range []string{slackToken, "XSECRETTOKEN", hookSecret, strings.TrimPrefix(hookSecret, domain.SecretPrefix)} {
			if strings.Contains(logs.String(), s) {
				t.Errorf("the log holds a channel secret: %s", logs.String())
			}
			if n := e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE position($1::bytea IN body) > 0", []byte(s)); n != 0 {
				t.Errorf("%d audit entries hold a channel secret", n)
			}
			if n := e.count(t, "SELECT count(*) FROM pc.deliveries WHERE position($1 IN coalesce(last_error, '')) > 0", s); n != 0 {
				t.Errorf("%d delivery errors hold a channel secret", n)
			}
		}

		// The Slack channel's sealed URL copied into the webhook's row does
		// not open there (HR-062), so nothing is sent with it.
		e.d.AdminExec(t, "UPDATE pc.notification_channels SET secret = (SELECT secret FROM pc.notification_channels WHERE id = $2) WHERE id = $1", hook.ID, slack.ID)
		e.enqueue(t, napp.Message{Type: "security.credential_removed", Params: registered("alice@example.test")})
		latest := p1tIDs(t, e, "SELECT id FROM pc.deliveries WHERE channel_id = $1 AND state = 'PENDING' ORDER BY created_at DESC, id DESC LIMIT 1", hook.ID)
		if len(latest) != 1 {
			t.Fatal("no pending webhook delivery")
		}
		_ = e.svc.Deliver(context.Background(), e.org, latest[0])
		if row := e.row(t, latest[0]); row.lastError != "secret_unavailable" || len(r.got()) != 2 {
			t.Fatalf("delivery with a moved secret: %+v, %d requests", row, len(r.got()))
		}
	})

	t.Run("mail", func(t *testing.T) {
		e := newEnv(t)
		admin := e.as(td.KindUser, e.alice, td.RoleOrgAdmin)
		for _, in := range []napp.ChannelInput{
			{Name: "strangers", Kind: domain.KindEmail, EventTypes: []string{"security.*"}, RecipientRole: "org_admin", URL: "mailto:stranger@evil.example"},
			{Name: "strangers", Kind: domain.KindEmail, EventTypes: []string{"security.*"}, RecipientRole: "stranger@evil.example"},
		} {
			if _, _, err := e.svc.CreateChannel(admin, in); !errors.Is(err, napp.ErrInvalidChannel) {
				t.Errorf("email channel %+v: %v, want ErrInvalidChannel", in, err)
			}
		}

		e.d.AdminExec(t, "UPDATE pc.users SET email = $2 WHERE id = $1", e.carol, "carol@example.test\r\nBcc: stranger@evil.example")
		s := smtptest.New(t)
		host, port, _ := net.SplitHostPort(s.Addr)
		p, _ := strconv.Atoi(port)
		m, err := smtpmail.New(smtpmail.Config{
			Host: host, Port: p, TLS: smtpmail.TLSStartTLS, From: "pantherclaw@example.test",
			Username: s.User, Password: pclog.NewSecret([]byte(s.Password)), HeloName: "pc.example.test", RootCAs: s.RootCAs,
		})
		if err != nil {
			t.Fatal(err)
		}
		e.svc.SetMailer(m)
		p1tSecurityNotice(t, e, authnapp.SecurityNotice{User: e.carol, Type: "security.credential_registered", Credential: ids.NewV7(), Name: "Desk key"})
		id := e.delivery(t)
		if err := e.svc.Deliver(context.Background(), e.org, id); err != nil {
			t.Fatalf("a refused address is retried: %v", err)
		}
		if row := e.row(t, id); row.state != "FAILED" || row.lastError != "mail_refused" {
			t.Fatalf("delivery %+v, want FAILED mail_refused", row)
		}
		if msgs := s.Messages(); len(msgs) != 0 {
			t.Fatalf("mail sent: %+v", msgs)
		}
	})
}

// TestT054_SpoofedLinksAndForgedWebhooksDoNotPass: T-054 — attacker text
// in a security notice (a key name forging a Slack link to an "approve"
// page) reaches Slack escaped, with exactly one link, to PantherClaw, and
// no blocks, buttons or unfurling; the webhook copy carries no such text
// and is signed, so a body changed in transit or a re-timestamped replay
// does not verify. TestHR158_* and TestHR159_* cover the pieces, including
// the absence of approve or deny actions in every message type.
func TestT054_SpoofedLinksAndForgedWebhooksDoNotPass(t *testing.T) {
	r := newReceiver(t)
	e := newEnv(t)
	e.svc.SetHTTPClient(p1tRouteAll(r))
	e.channel(t, napp.NewChannel{Name: "chat", Kind: domain.KindSlack, EventTypes: []string{"security.*"}, URL: "https://hooks.slack.com/services/T0/B0/XYZ"})
	hook := e.channel(t, napp.NewChannel{Name: "siem", Kind: domain.KindWebhook, EventTypes: []string{"security.*"}, URL: "https://hooks.example.com/pc"})
	p1tSecurityNotice(t, e, authnapp.SecurityNotice{
		User: e.alice, Type: "security.credential_suspended", Credential: ids.NewV7(), Name: "<https://evil.example/approve|Approve in PantherClaw>",
	})
	p1tDeliverAll(t, e)
	var slack, webhook *recorded
	for _, q := range r.got() {
		switch q.host {
		case domain.SlackHost:
			slack = q
		case "hooks.example.com":
			webhook = q
		}
	}
	if slack == nil || webhook == nil {
		t.Fatalf("requests %d: Slack %t, webhook %t", len(r.got()), slack != nil, webhook != nil)
	}

	var msg map[string]any
	if err := json.Unmarshal(slack.body, &msg); err != nil {
		t.Fatal(err)
	}
	text, _ := msg["text"].(string)
	link := "<https://pc.example.test/account?org=" + e.org.String() + "|Open in PantherClaw>"
	if strings.Contains(text, "<https://evil") || !strings.Contains(text, "&lt;https://evil.example/approve|Approve in PantherClaw&gt;") {
		t.Errorf("the forged link is not escaped: %q", text)
	}
	if strings.Count(text, "<") != 1 || !strings.HasSuffix(text, link) {
		t.Errorf("the message must end with its one link, to PantherClaw: %q", text)
	}
	if len(msg) != 3 || msg["unfurl_links"] != false || msg["unfurl_media"] != false {
		t.Errorf("Slack message %s: want text only, without unfurling", slack.body)
	}

	if bytes.Contains(webhook.body, []byte("evil.example")) {
		t.Errorf("the webhook carries the key name: %s", webhook.body)
	}
	if !verify(t, hook.Secret, webhook.header, webhook.body) {
		t.Fatal("the webhook does not verify with its secret")
	}
	forged := bytes.Replace(webhook.body, []byte(`"security.credential_suspended"`), []byte(`"approval.decided"`), 1)
	if bytes.Equal(forged, webhook.body) || verify(t, hook.Secret, webhook.header, forged) {
		t.Error("a changed body verifies")
	}
	replayed := webhook.header.Clone()
	replayed.Set("webhook-timestamp", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
	if verify(t, hook.Secret, replayed, webhook.body) {
		t.Error("a re-timestamped replay verifies")
	}
}

// TestT054_AFloodedChannelCannotSilenceTheOthers: T-054 — when one
// channel's queue is full (1,000 pending deliveries), a new security
// notice is dropped for that channel alone, without a job, and still
// reaches the other channel and, by email, the person it concerns.
// TestHR159_QueuesAreBoundedAndNoticesDeduplicated covers the cap and
// deduplication.
func TestT054_AFloodedChannelCannotSilenceTheOthers(t *testing.T) {
	e := newEnv(t)
	busy := e.channel(t, napp.NewChannel{Name: "busy", Kind: domain.KindLog, EventTypes: []string{"security.*"}})
	quiet := e.channel(t, napp.NewChannel{Name: "quiet", Kind: domain.KindLog, EventTypes: []string{"security.*"}})
	flood := e.enqueue(t, napp.Message{Type: "security.credential_registered", Params: registered("alice")})
	e.exec(t, `INSERT INTO pc.deliveries (org_id, id, notification_id, channel_id, kind)
		SELECT $1, gen_random_uuid(), $2, $3, 'log' FROM generate_series(1, $4)`, e.org, flood.Notification, busy.ID, napp.MaxPendingPerChannel)
	p1tSecurityNotice(t, e, authnapp.SecurityNotice{User: e.alice, Type: "security.credential_suspended", Credential: ids.NewV7(), Name: "Desk key"})

	const of = " AND notification_id = (SELECT id FROM pc.notifications WHERE type = 'security.credential_suspended')"
	dropped := p1tIDs(t, e, "SELECT id FROM pc.deliveries WHERE channel_id = $1 AND state = 'DROPPED' AND last_error = 'queue_full'"+of, busy.ID)
	if len(dropped) != 1 {
		t.Fatalf("%d dropped deliveries on the full channel, want 1", len(dropped))
	}
	var jobsForDropped int
	e.d.AdminQueryRow(t, "SELECT count(*) FROM pc.river_job WHERE kind = 'notifications.deliver' AND args->>'delivery' = $1",
		[]any{dropped[0].String()}, &jobsForDropped)
	if jobsForDropped != 0 {
		t.Errorf("%d jobs for a dropped delivery", jobsForDropped)
	}
	if n := len(p1tIDs(t, e, "SELECT id FROM pc.deliveries WHERE channel_id = $1 AND state = 'PENDING'"+of, quiet.ID)); n != 1 {
		t.Errorf("%d pending deliveries on the other channel, want 1", n)
	}
	if n := len(p1tIDs(t, e, "SELECT id FROM pc.deliveries WHERE channel_id IS NULL AND kind = 'email' AND recipient_user_id = $1 AND state = 'PENDING'"+of, e.alice)); n != 1 {
		t.Errorf("%d pending emails to the key's owner, want 1", n)
	}
}
