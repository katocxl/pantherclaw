// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

func denied(host string) bool { return httpx.DeniedHost(host, nil) }

// TestHR159_StandardWebhooksSignature checks the signature against the
// Standard Webhooks reference test vector (the spec's own example).
func TestHR159_StandardWebhooksSignature(t *testing.T) {
	secret, err := base64.StdEncoding.DecodeString(strings.TrimPrefix("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", domain.SecretPrefix))
	if err != nil {
		t.Fatal(err)
	}
	got := domain.Sign(secret, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, []byte(`{"test": 2432232314}`)) // gitleaks:allow -- the public Standard Webhooks test vector, not a secret
	if want := "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="; got != want {
		t.Fatalf("signature %s, want %s", got, want)
	}
	if s := domain.FormatSecret(secret); s != "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw" {
		t.Fatalf("formatted secret %s", s)
	}
	// During a rotation both signatures are sent, current first.
	other := []byte("another secret of thirty-two by!")
	both := domain.Signatures([][]byte{secret, other}, "msg_1", 1, []byte("{}"))
	parts := strings.Split(both, " ")
	if len(parts) != 2 || parts[0] != domain.Sign(secret, "msg_1", 1, []byte("{}")) || parts[1] != domain.Sign(other, "msg_1", 1, []byte("{}")) {
		t.Fatalf("signatures %q", both)
	}
	if domain.Sign(secret, "msg_1", 1, []byte("{}")) == domain.Sign(secret, "msg_1", 2, []byte("{}")) {
		t.Fatal("the timestamp is not signed")
	}
}

func TestHR157_WebhookDestinations(t *testing.T) {
	for _, u := range []string{
		"https://hooks.example.com/pantherclaw",
		"https://hooks.example.com:8443/pc?team=7",
		"https://8.8.8.8/hook",
	} {
		if err := domain.CheckWebhookURL(u, "pc.example.test", denied); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for u, want := range map[string]error{
		"http://hooks.example.com/pc":          domain.ErrBadURL,
		"https://user:pw@hooks.example.com/":   domain.ErrBadURL,
		"https://hooks.example.com/#frag":      domain.ErrBadURL,
		"https://hooks.example.com:22/":        domain.ErrBadURL,
		"https://hooks.example.com:80/":        domain.ErrBadURL,
		"https://hooks.example.com/a b":        domain.ErrBadURL,
		"ftp://hooks.example.com/":             domain.ErrBadURL,
		"https://localhost/hook":               domain.ErrPrivateURL,
		"https://api.localhost/hook":           domain.ErrPrivateURL,
		"https://127.0.0.1/hook":               domain.ErrPrivateURL,
		"https://10.0.0.5/hook":                domain.ErrPrivateURL,
		"https://169.254.169.254/latest/":      domain.ErrPrivateURL,
		"https://[::1]/hook":                   domain.ErrPrivateURL,
		"https://[::ffff:127.0.0.1]/hook":      domain.ErrPrivateURL,
		"https://100.64.0.1/hook":              domain.ErrPrivateURL,
		"https://pc.example.test/oauth2/token": domain.ErrOwnHost,
		"https://PC.Example.Test./hook":        domain.ErrOwnHost,
	} {
		if err := domain.CheckWebhookURL(u, "pc.example.test", denied); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", u, err, want)
		}
	}
	// An operator-allowed range re-allows a private address (self-hosted).
	allowed := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if err := domain.CheckWebhookURL("https://10.0.0.5/hook", "pc.example.test", func(h string) bool { return httpx.DeniedHost(h, allowed) }); err != nil {
		t.Errorf("allowed private range: %v", err)
	}
}

// TestHR157_AWebhookIsRefusedInEverySpellingOfADeniedHost (HR-077): when a
// channel is saved, the host is read the way the egress guard reads it, so
// the metadata address in decimal, octal, hex, short or IPv6 forms, a
// metadata host name, and other spellings of loopback and private
// addresses are refused then, not only when delivery dials. An operator's
// allowed range re-allows its private addresses in any spelling, never
// metadata.
func TestHR157_AWebhookIsRefusedInEverySpellingOfADeniedHost(t *testing.T) {
	metadata := []string{
		"https://2852039166/latest/meta-data/", // decimal
		"https://0xa9fea9fe/",                  // hex
		"https://0XA9FEA9FE/",
		"https://0xa9.0xfe.0xa9.0xfe/",
		"https://0251.0376.0251.0376/", // octal
		"https://169.254.43518/",       // a.b.cd
		"https://169.16689662/",        // a.bcd
		"https://169.254.169.254./",    // trailing dot
		"https://[::ffff:169.254.169.254]/",
		"https://[::ffff:a9fe:a9fe]/",   // IPv4-mapped
		"https://[64:ff9b::a9fe:a9fe]/", // NAT64
		"https://[fd00:ec2::254]/",      // AWS IMDS over IPv6
		"https://1684301000:8443/",      // 100.100.100.200, Alibaba Cloud
		"https://metadata.google.internal/computeMetadata/v1/",
		"https://METADATA.Google.Internal./",
		"https://metadata/",
		"https://metadata.goog/",
		"https://instance-data.ec2.internal/",
		"https://metadata.azure.com/",
	}
	private := []string{
		"https://2130706433/",   // 127.0.0.1
		"https://017700000001/", // 127.0.0.1, octal
		"https://0x7f.1/",
		"https://127.1/",
		"https://0/",
		"https://[::ffff:7f00:1]/",
		"https://167772165/", // 10.0.0.5
		"https://0xa.0.0.5/",
		"https://[::ffff:10.0.0.5]/",
		"https://[fe80::a9fe:a9fe%25eth0]/", // zoned link-local
	}
	for _, u := range append(slices.Clone(metadata), private...) {
		if err := domain.CheckWebhookURL(u, "pc.example.test", denied); !errors.Is(err, domain.ErrPrivateURL) {
			t.Errorf("%s: %v, want %v", u, err, domain.ErrPrivateURL)
		}
	}
	operator := func(h string) bool {
		return httpx.DeniedHost(h, []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
			netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
		})
	}
	for _, u := range metadata {
		if err := domain.CheckWebhookURL(u, "pc.example.test", operator); !errors.Is(err, domain.ErrPrivateURL) {
			t.Errorf("%s inside an allowed range: %v, want %v", u, err, domain.ErrPrivateURL)
		}
	}
	for _, u := range []string{"https://167772165/", "https://0xa.0.0.5/", "https://012.0.0.5:8443/"} {
		if err := domain.CheckWebhookURL(u, "pc.example.test", operator); err != nil {
			t.Errorf("%s inside an allowed range: %v", u, err)
		}
	}
	// Public addresses in other spellings, and names that only look like
	// metadata or numbers, are still accepted.
	for _, u := range []string{
		"https://134744072/hook", "https://[::ffff:8.8.8.8]/hook", "https://metadata.example.com/",
		"https://1password.example/hook", "https://metadata.google.internal.example/",
	} {
		if err := domain.CheckWebhookURL(u, "pc.example.test", denied); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}

func TestHR157_SlackDestinations(t *testing.T) {
	if err := domain.CheckSlackURL("https://hooks.slack.com/services/T000/B000/XXXX"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{
		"http://hooks.slack.com/services/T/B/X",
		"https://hooks.slack.com.evil.example/services/T/B/X",
		"https://evil.example/services/T/B/X",
		"https://hooks.slack.com/api/chat.postMessage",
		"https://hooks.slack.com/services/T/B/X?redirect=1",
		"https://hooks.slack.com:8443/services/T/B/X",
		"https://user@hooks.slack.com/services/T/B/X",
		"https://hooks.slack.com/services/../../x",
	} {
		if err := domain.CheckSlackURL(u); !errors.Is(err, domain.ErrSlackURL) {
			t.Errorf("%s: %v", u, err)
		}
	}
}

func TestHR158_TemplatesRenderOnlyDeclaredPlainParameters(t *testing.T) {
	r, err := domain.Render("security.credential_registered", map[string]string{"user": "Alice", "key_name": "Desk key"})
	if err != nil || r.Severity != domain.Warning || r.Link != "/account" || !strings.Contains(r.Body, `"Desk key"`) || !strings.Contains(r.Body, "Alice") {
		t.Fatalf("render: %+v %v", r, err)
	}
	for name, params := range map[string]map[string]string{
		"missing parameter": {"user": "Alice"},
		"extra parameter":   {"user": "Alice", "key_name": "k", "link": "https://evil.example"},
		"newline":           {"user": "Alice\nApprove now", "key_name": "k"},
		"bidi":              {"user": "Alice" + string(rune(0x202e)) + "evil", "key_name": "k"},
		"line separator":    {"user": "Alice" + string(rune(0x2028)), "key_name": "k"},
		"empty":             {"user": "", "key_name": "k"},
		"too long":          {"user": strings.Repeat("a", 201), "key_name": "k"},
	} {
		if _, err := domain.Render("security.credential_registered", params); !errors.Is(err, domain.ErrBadParams) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := domain.Render("approval.approve_now", nil); !errors.Is(err, domain.ErrUnknownType) {
		t.Error("an unregistered type rendered")
	}
	// No template offers an action: approvals are never decided in a channel.
	for _, typ := range domain.Types() {
		tm, _ := domain.Lookup(typ)
		lower := strings.ToLower(tm.Title + " " + tm.Body)
		for _, word := range []string{"approve", "reply", "react", "click here"} {
			if strings.Contains(lower, word) {
				t.Errorf("%s mentions %q", typ, word)
			}
		}
		if tm.Link != "" && !strings.HasPrefix(tm.Link, "/") {
			t.Errorf("%s links outside PantherClaw: %s", typ, tm.Link)
		}
	}
}

func TestSubscriptions(t *testing.T) {
	if err := domain.ValidEventTypes([]string{"security.*", "channel.test"}); err != nil {
		t.Fatal(err)
	}
	for _, ps := range [][]string{nil, {"*"}, {"security"}, {"Security.*"}, {"security.*.x"}, {strings.Repeat("a.", 40) + "b"}} {
		if domain.ValidEventTypes(ps) == nil {
			t.Errorf("%q accepted", ps)
		}
	}
	if !domain.Matches([]string{"security.*"}, "security.credential_removed") || domain.Matches([]string{"security.*"}, "securityx.y") ||
		domain.Matches([]string{"channel.test"}, "channel.tests") {
		t.Fatal("pattern matching")
	}
	if !domain.Critical.AtLeast(domain.Warning) || domain.Info.AtLeast(domain.Warning) {
		t.Fatal("severity order")
	}
}

func TestHR159_RetryScheduleAndHealth(t *testing.T) {
	var total time.Duration
	for n := 1; n < domain.MaxAttempts; n++ {
		total += domain.RetryDelay(n)
	}
	if domain.RetryDelay(1) != 5*time.Second || domain.RetryDelay(2) != 5*time.Minute || domain.RetryDelay(7) != 10*time.Hour ||
		domain.RetryDelay(99) != 10*time.Hour || total < 27*time.Hour || total > 28*time.Hour {
		t.Fatalf("schedule total %s", total)
	}
	if domain.HealthOf(0) != domain.Healthy || domain.HealthOf(3) != domain.Degraded || domain.HealthOf(domain.FailingAfter) != domain.Failing {
		t.Fatal("health levels")
	}
}

func TestHR158_SlackTextHasOneLinkAndNoMarkup(t *testing.T) {
	got := domain.SlackText("Key <added>", "by <!channel> & <https://evil.example|you>", "https://pc.example.test/account?org=o")
	if strings.Count(got, "<") != 1 || strings.Contains(got, "<!channel>") || !strings.HasSuffix(got, "<https://pc.example.test/account?org=o|Open in PantherClaw>") {
		t.Fatalf("slack text %q", got)
	}
}

// TestHR173_ApprovalNoticesLinkOnlyToTheirRequest (G0 M5 part 2): an
// approval notice links to its request's approval page, and only a
// canonical id fills the link.
func TestHR173_ApprovalNoticesLinkOnlyToTheirRequest(t *testing.T) {
	params := map[string]string{
		"operation": "payments.refund.create", "agent": "019a0000-0000-7000-8000-000000000001",
		"deadline": "2026-10-10T13:00:00Z", "request": "019a0000-0000-7000-8000-000000000002",
	}
	r, err := domain.Render("approval.requested", params)
	if err != nil || r.Link != "/approvals/019a0000-0000-7000-8000-000000000002" || r.Severity != domain.Warning {
		t.Fatalf("render: %+v, %v", r, err)
	}
	for _, bad := range []string{"../account", "https://evil.example", "019A0000-0000-7000-8000-000000000002", "x"} {
		params["request"] = bad
		if _, err := domain.Render("approval.requested", params); !errors.Is(err, domain.ErrBadParams) {
			t.Errorf("request %q: %v", bad, err)
		}
	}
}
