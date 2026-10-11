// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
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

// serveM5 starts the server with cfgPath and returns its base URL; it stops
// when the test ends.
func serveM5(t *testing.T, cfgPath string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	addrCh := make(chan string, 1)
	done := make(chan error, 1)
	var logs bytes.Buffer
	go func() {
		done <- cmdServe(ctx, []string{"--config", cfgPath}, &logs, noEnv, func(a string) { addrCh <- a })
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("graceful shutdown did not finish")
		}
	})
	select {
	case a := <-addrCh:
		return "http://" + a
	case err := <-done:
		t.Fatalf("serve exited early: %v\n%s", err, logs.String())
	case <-time.After(60 * time.Second):
		t.Fatal("server did not start")
	}
	return ""
}

func statusM5(t *testing.T, method, url string) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, url, nil)
	c := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestIntServeM5PagesServicesAndDeliveries(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAll)
	base := serveM5(t, cfgPath)
	org := ids.New[ids.Org]()

	// The pages are mounted; without a session the account page sends the
	// browser to sign in for the org in the link.
	if code := statusM5(t, http.MethodGet, base+"/account?org="+org.String()); code != http.StatusSeeOther {
		t.Errorf("/account = %d, want 303", code)
	}
	if code := statusM5(t, http.MethodGet, base+"/static/account.js"); code != http.StatusOK {
		t.Errorf("/static/account.js = %d", code)
	}
	// The public URL is an IP address: security keys are off, their routes absent.
	if code := statusM5(t, http.MethodPost, base+"/account/keys/registration-options"); code != http.StatusNotFound {
		t.Errorf("key routes with WebAuthn off = %d, want 404", code)
	}
	// Both services are served (and refuse an anonymous caller).
	hc := &http.Client{Timeout: 5 * time.Second}
	acct := pantherclawv1connect.NewAccountServiceClient(connect.NewClient(connecthttp.NewTransport(hc, base)))
	if _, err := acct.ListMySessions(context.Background(), &pantherclawv1.ListMySessionsRequest{}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("AccountService anonymous: %v", err)
	}
	notif := pantherclawv1connect.NewNotificationServiceClient(connect.NewClient(connecthttp.NewTransport(hc, base)))
	if _, err := notif.ListChannels(context.Background(), &pantherclawv1.ListChannelsRequest{}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("NotificationService anonymous: %v", err)
	}

	// The worker delivers what the API enqueues, on its own queue.
	pool := d.AppPool(t)
	kek := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{kek})
	if err != nil {
		t.Fatal(err)
	}
	insert, err := jobs.NewClient(pool, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := napp.New(pool, insert, pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp)), napp.Config{PublicURL: "http://127.0.0.1:8080"}, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'wired')", org); err != nil {
			return err
		}
		if _, err := svc.CreateChannelTx(ctx, tx, napp.NewChannel{
			Org: org, Name: "ops", Kind: domain.KindLog,
			EventTypes: []string{"channel.test"}, CreatedBy: "test",
		}); err != nil {
			return err
		}
		_, err := svc.Enqueue(ctx, tx, napp.Message{Org: org, Type: "channel.test", Params: map[string]string{"channel": "ops"}})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		var state string
		err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT state FROM pc.deliveries").Scan(&state)
		})
		if err != nil {
			t.Fatal(err)
		}
		if state == "DELIVERED" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("delivery is %s after 30 s, want DELIVERED", state)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestIntServeMountsKeyRoutesForADomainName(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAPI, func(m map[string]any) {
		m["auth"] = map[string]any{"public_url": "http://localhost:8080"}
	})
	base := serveM5(t, cfgPath)
	// Mounted: a POST without the CSRF proof is refused by the route itself.
	if code := statusM5(t, http.MethodPost, base+"/account/keys/registration-options"); code != http.StatusForbidden {
		t.Errorf("key routes with WebAuthn on = %d, want 403 (CSRF)", code)
	}
}
