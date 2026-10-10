// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/keystore"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

type env struct {
	d        *dbtest.DB
	pool     *db.Pool
	svc      *napp.Service
	envelope *pccrypto.Envelope
	org      ids.OrgID
	alice    ids.UUID // org admin
	bob      ids.UUID // org admin
	carol    ids.UUID // viewer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvConfig(t, napp.Config{PublicURL: "https://pc.example.test"})
}

func newEnvConfig(t *testing.T, cfg napp.Config) *env {
	t.Helper()
	d := dbtest.New(t)
	pool := d.AppPool(t)
	p := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(p); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	envelope := pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp))
	jc, err := jobs.NewClient(pool, nil, jobs.Config{}) // insert-only, as in the API role
	if err != nil {
		t.Fatal(err)
	}
	svc, err := napp.New(pool, jc, envelope, cfg, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{d: d, pool: pool, svc: svc, envelope: envelope, org: ids.New[ids.Org](), alice: ids.NewV7(), bob: ids.NewV7(), carol: ids.NewV7()}
	e.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'notify')", e.org)
	for i, u := range []ids.UUID{e.alice, e.bob, e.carol} {
		name := []string{"alice", "bob", "carol"}[i]
		role := []string{"org_admin", "org_admin", "viewer"}[i]
		e.exec(t, `INSERT INTO pc.users (org_id, id, issuer, subject, email) VALUES ($1, $2, 'https://idp.test', $3, $4)`,
			e.org, u, name, name+"@example.test")
		e.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
			e.org, ids.NewV7(), role, u)
	}
	return e
}

func (e *env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (e *env) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) channel(t *testing.T, in napp.NewChannel) napp.CreatedChannel {
	t.Helper()
	in.Org, in.CreatedBy = e.org, "test"
	var out napp.CreatedChannel
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = e.svc.CreateChannelTx(ctx, tx, in)
		return err
	}); err != nil {
		t.Fatalf("channel %s: %v", in.Name, err)
	}
	return out
}

func (e *env) enqueue(t *testing.T, m napp.Message) napp.Enqueued {
	t.Helper()
	m.Org = e.org
	var out napp.Enqueued
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = e.svc.Enqueue(ctx, tx, m)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func registered(user string) map[string]string {
	return map[string]string{"user": user, "key_name": "Desk key"}
}

func TestHR159_EnqueueIsAnOutbox(t *testing.T) {
	e := newEnv(t)
	e.channel(t, napp.NewChannel{Name: "ops-log", Kind: domain.KindLog, EventTypes: []string{"security.*"}})
	// A rolled-back change sends nothing.
	rollback := errors.New("rollback")
	err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := e.svc.Enqueue(ctx, tx, napp.Message{Org: e.org, Type: "security.credential_registered", Params: registered("alice")}); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.notifications") + e.count(t, "SELECT count(*) FROM pc.deliveries"); n != 0 {
		t.Fatalf("%d rows after a rollback", n)
	}
	var jobsAfterRollback int
	e.d.AdminQueryRow(t, "SELECT count(*) FROM pc.river_job WHERE kind = 'notifications.deliver'", nil, &jobsAfterRollback)
	if jobsAfterRollback != 0 {
		t.Fatalf("%d jobs after a rollback", jobsAfterRollback)
	}
	// A committed change has its deliveries and one job each, carrying ids only (HR-056).
	out := e.enqueue(t, napp.Message{Type: "security.credential_registered", Params: registered("alice")})
	if out.Deliveries != 1 {
		t.Fatalf("deliveries %d, want 1", out.Deliveries)
	}
	var args string
	var maxAttempts int
	var queue string
	e.d.AdminQueryRow(t, "SELECT args::text, max_attempts, queue FROM pc.river_job WHERE kind = 'notifications.deliver'", nil, &args, &maxAttempts, &queue)
	var delivery ids.UUID
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT id FROM pc.deliveries").Scan(&delivery)
	}); err != nil {
		t.Fatal(err)
	}
	want := `{"org": "` + e.org.String() + `", "delivery": "` + delivery.String() + `"}`
	if args != want || maxAttempts != napp.MaxAttempts || queue != napp.Queue {
		t.Fatalf("job args %s (want %s), max attempts %d, queue %s", args, want, maxAttempts, queue)
	}
}

func TestHR158_RoutingFollowsSubscriptionsAndRoles(t *testing.T) {
	e := newEnv(t)
	e.channel(t, napp.NewChannel{Name: "ops-log", Kind: domain.KindLog, EventTypes: []string{"security.*"}})
	e.channel(t, napp.NewChannel{Name: "only-tests", Kind: domain.KindLog, EventTypes: []string{"channel.test"}})
	e.channel(t, napp.NewChannel{
		Name: "pager", Kind: domain.KindSlack, EventTypes: []string{"security.*"}, MinSeverity: domain.Critical,
		URL: "https://hooks.slack.com/services/T0/B0/X",
	})
	e.channel(t, napp.NewChannel{Name: "admins", Kind: domain.KindEmail, EventTypes: []string{"security.*"}, RecipientRole: "org_admin"})
	paused := e.channel(t, napp.NewChannel{Name: "paused", Kind: domain.KindLog, EventTypes: []string{"security.*"}})
	e.exec(t, "UPDATE pc.notification_channels SET state = 'PAUSED', pause_reason = 'MANUAL' WHERE id = $1", paused.ID)

	// A WARNING security notice for alice: alice personally; the log
	// channel; the admins channel to bob only (alice is already emailed);
	// the paused channel SKIPPED; not the CRITICAL-only Slack channel or
	// the channel.test subscription; never carol (a viewer).
	out := e.enqueue(t, napp.Message{Type: "security.credential_registered", Params: registered("alice"), Personal: []ids.UUID{e.alice}})
	if out.Deliveries != 4 {
		t.Fatalf("deliveries %d, want 4", out.Deliveries)
	}
	for _, c := range []struct {
		sql  string
		args []any
		want int
	}{
		{"SELECT count(*) FROM pc.deliveries WHERE kind = 'email' AND channel_id IS NULL AND recipient_user_id = $1", []any{e.alice}, 1},
		{"SELECT count(*) FROM pc.deliveries WHERE kind = 'email' AND channel_id IS NOT NULL AND recipient_user_id = $1", []any{e.bob}, 1},
		{"SELECT count(*) FROM pc.deliveries WHERE recipient_user_id = $1", []any{e.carol}, 0},
		{"SELECT count(*) FROM pc.deliveries WHERE kind = 'slack'", nil, 0},
		{"SELECT count(*) FROM pc.deliveries WHERE state = 'SKIPPED' AND channel_id = $1 AND last_error = 'channel_paused'", []any{paused.ID}, 1},
		{"SELECT count(*) FROM pc.deliveries WHERE state = 'PENDING'", nil, 3},
	} {
		if n := e.count(t, c.sql, c.args...); n != c.want {
			t.Errorf("%s: %d, want %d", c.sql, n, c.want)
		}
	}
	// A CRITICAL one reaches the pager too.
	e.enqueue(t, napp.Message{Type: "security.credential_suspended", Params: registered("alice")})
	if n := e.count(t, "SELECT count(*) FROM pc.deliveries WHERE kind = 'slack'"); n != 1 {
		t.Errorf("critical notice: %d Slack deliveries, want 1", n)
	}
	// Templates refuse anything but their declared plain parameters.
	err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := e.svc.Enqueue(ctx, tx, napp.Message{
			Org: e.org, Type: "security.credential_registered",
			Params: map[string]string{"user": "alice\nApprove the refund", "key_name": "k"},
		})
		return err
	})
	if !errors.Is(err, domain.ErrBadParams) {
		t.Errorf("multi-line parameter: %v", err)
	}
}

func TestHR159_QueuesAreBoundedAndNoticesDeduplicated(t *testing.T) {
	e := newEnv(t)
	ch := e.channel(t, napp.NewChannel{Name: "busy", Kind: domain.KindLog, EventTypes: []string{"security.*"}})
	first := e.enqueue(t, napp.Message{Type: "security.credential_registered", Params: registered("alice")})
	e.exec(t, `INSERT INTO pc.deliveries (org_id, id, notification_id, channel_id, kind)
		SELECT $1, gen_random_uuid(), $2, $3, 'log' FROM generate_series(1, $4)`, e.org, first.Notification, ch.ID, napp.MaxPendingPerChannel)
	out := e.enqueue(t, napp.Message{Type: "security.credential_registered", Params: registered("alice")})
	if out.Deliveries != 1 || e.count(t, "SELECT count(*) FROM pc.deliveries WHERE state = 'DROPPED' AND last_error = 'queue_full'") != 1 {
		t.Fatal("a full channel queue did not drop the delivery")
	}
	if e.count(t, "SELECT count(*) FROM pc.notification_channels WHERE last_failure_code = 'queue_full'") != 1 {
		t.Error("the full channel was not flagged")
	}
	dup := napp.Message{Type: "notification.channel_paused", Params: map[string]string{"channel": "busy", "reason": "failing"}, DedupeKey: "paused:" + ch.ID.String()}
	if a, b := e.enqueue(t, dup), e.enqueue(t, dup); a.Duplicate || !b.Duplicate || b.Deliveries != 0 {
		t.Fatalf("dedupe: %+v %+v", a, b)
	}
}

func TestHR157_ChannelsValidateAndEncryptTheirSecrets(t *testing.T) {
	e := newEnv(t)
	hook := e.channel(t, napp.NewChannel{Name: "siem", Kind: domain.KindWebhook, EventTypes: []string{"security.*"}, URL: "https://hooks.example.com/pc"})
	if len(hook.Secret) < 40 || hook.Secret[:6] != domain.SecretPrefix {
		t.Fatalf("webhook secret %q", hook.Secret)
	}
	const slackURL = "https://hooks.slack.com/services/T0/B0/SECRETPART"
	slack := e.channel(t, napp.NewChannel{Name: "chat", Kind: domain.KindSlack, EventTypes: []string{"security.*"}, URL: slackURL})
	var blob []byte
	var url *string
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT secret, url FROM pc.notification_channels WHERE id = $1", slack.ID).Scan(&blob, &url)
	}); err != nil {
		t.Fatal(err)
	}
	if url != nil || bytes.Contains(blob, []byte("SECRETPART")) {
		t.Fatal("the Slack URL is stored in clear")
	}
	fc := func(id ids.UUID, col string) pccrypto.FieldContext {
		return pccrypto.FieldContext{Org: e.org, Table: "notification_channels", Column: col, RowID: id.String()}
	}
	ctx := context.Background()
	if plain, err := e.envelope.Decrypt(ctx, fc(slack.ID, "secret"), napp.SecretPurpose, blob); err != nil || string(plain) != slackURL {
		t.Fatalf("own row: %q %v", plain, err)
	}
	for name, f := range map[string]pccrypto.FieldContext{"another channel": fc(hook.ID, "secret"), "another column": fc(slack.ID, "prev_secret")} {
		if _, err := e.envelope.Decrypt(ctx, f, napp.SecretPurpose, blob); err == nil {
			t.Errorf("the secret decrypts for %s (HR-062)", name)
		}
	}

	bad := []napp.NewChannel{
		{Name: "h1", Kind: domain.KindWebhook, EventTypes: []string{"security.*"}, URL: "http://hooks.example.com/pc"},
		{Name: "h2", Kind: domain.KindWebhook, EventTypes: []string{"security.*"}, URL: "https://169.254.169.254/latest"},
		{Name: "h3", Kind: domain.KindWebhook, EventTypes: []string{"security.*"}, URL: "https://pc.example.test/oauth2/token"},
		{Name: "s1", Kind: domain.KindSlack, EventTypes: []string{"security.*"}, URL: "https://evil.example/services/x"},
		{Name: "e1", Kind: domain.KindEmail, EventTypes: []string{"security.*"}, RecipientRole: "everyone"},
		{Name: "e2", Kind: domain.KindEmail, EventTypes: []string{"security.*"}, RecipientRole: "org_admin", URL: "https://x.example"},
		{Name: "l1", Kind: domain.KindLog, EventTypes: []string{"*"}},
		{Name: "l2", Kind: domain.KindLog, EventTypes: []string{"security.*"}, RecipientRole: "org_admin"},
		{Name: "Bad Name", Kind: domain.KindLog, EventTypes: []string{"security.*"}},
	}
	for _, in := range bad {
		in.Org, in.CreatedBy = e.org, "test"
		err := e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := e.svc.CreateChannelTx(ctx, tx, in)
			return err
		})
		if err == nil {
			t.Errorf("channel %+v was accepted", in)
		}
	}
	in := napp.NewChannel{Org: e.org, CreatedBy: "test", Name: "siem", Kind: domain.KindLog, EventTypes: []string{"security.*"}}
	err := e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := e.svc.CreateChannelTx(ctx, tx, in)
		return err
	})
	if !errors.Is(err, napp.ErrChannelExists) {
		t.Errorf("duplicate name: %v", err)
	}
}

func TestHR155_SecurityNoticesEmailTheUser(t *testing.T) {
	e := newEnv(t)
	cred := ids.NewV7()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return e.svc.SecurityNotice(ctx, tx, authnapp.SecurityNotice{
			Org: e.org, User: e.carol, Type: "security.credential_removed", Credential: cred, Name: "Old key",
		})
	}); err != nil {
		t.Fatal(err)
	}
	var title, body string
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT n.title, n.body FROM pc.notifications n JOIN pc.deliveries d ON d.notification_id = n.id
			WHERE d.recipient_user_id = $1 AND d.channel_id IS NULL AND n.subject_id = $2`, e.carol, cred).Scan(&title, &body)
	}); err != nil {
		t.Fatal(err)
	}
	if title != "A security key was removed from a PantherClaw account" || !bytes.Contains([]byte(body), []byte(`"Old key"`)) ||
		!bytes.Contains([]byte(body), []byte("carol@example.test")) {
		t.Fatalf("notice %q / %q", title, body)
	}
}

// TestHR039_FailedNoticesAreReportedPerSubject (G0 M5 part 2): the
// subjects whose notices failed, for a waitlist entry's routing health;
// personal-only notices skip the channels; an approval notice links to its
// request.
func TestHR039_FailedNoticesAreReportedPerSubject(t *testing.T) {
	e := newEnv(t)
	e.channel(t, napp.NewChannel{Name: "approvals-log", Kind: "log", EventTypes: []string{"approval.*"}, MinSeverity: "INFO"})
	failing, fine := ids.NewV7(), ids.NewV7()
	request := "019a0000-0000-7000-8000-000000000002"
	params := map[string]string{"operation": "payments.refund.create", "agent": failing.String(), "deadline": "2026-10-10T13:00:00Z", "request": request}
	out := e.enqueue(t, napp.Message{
		Type: "approval.requested", Params: params, Personal: []ids.UUID{e.carol},
		Subject: &napp.Subject{Type: "waitlist_entry", ID: failing},
	})
	if len(out.Channels) != 1 || out.Deliveries != 2 {
		t.Fatalf("enqueued %+v", out)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.notifications WHERE id = $1 AND link_path = $2", out.Notification, "/approvals/"+request); n != 1 {
		t.Fatal("the notice does not link to its request")
	}
	only := e.enqueue(t, napp.Message{
		Type: "approval.requested", Params: params, Personal: []ids.UUID{e.carol}, PersonalOnly: true,
		Subject: &napp.Subject{Type: "waitlist_entry", ID: fine},
	})
	if len(only.Channels) != 0 || only.Deliveries != 1 {
		t.Fatalf("personal only: %+v", only)
	}
	e.exec(t, "UPDATE pc.deliveries SET state = 'FAILED', finished_at = now() WHERE notification_id = $1 AND kind = 'email'", out.Notification)
	var got []ids.UUID
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		got, err = e.svc.FailedSubjects(ctx, tx, e.org, "waitlist_entry", []ids.UUID{failing, fine})
		return err
	}); err != nil || len(got) != 1 || got[0] != failing {
		t.Fatalf("failed subjects %v, %v", got, err)
	}
}
