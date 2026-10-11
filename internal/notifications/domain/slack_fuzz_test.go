// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/notifications/domain"
)

// slackUnescape reverses SlackEscape (Slack's own reading of &amp;, &lt;
// and &gt;).
var slackUnescape = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&")

// FuzzSlackEscape (G0 M5 part 1, HR-158): no title, body or link panics,
// escaped text holds none of Slack's control characters and reads back as
// the original, and a Slack message has exactly one link, the PantherClaw
// one, and no mention, channel ping or other markup a parameter could
// open.
func FuzzSlackEscape(f *testing.F) {
	f.Add("Key <added>", "by <!channel> & <https://evil.example|you>", "https://pc.example.test/account?org=o")
	f.Add("Approval requested", "payments.refund.create &lt;b&gt;", "https://pc.example.test/approvals/019a0000-0000-7000-8000-000000000002")
	f.Add("<@U123>", "<#C123|general> <!here> <!subteam^S1>", "")
	f.Add("&amp;", "&&lt;<>>", "https://pc.example.test/x>|<y")
	f.Fuzz(func(t *testing.T, title, body, link string) {
		for _, s := range []string{title, body, link} {
			e := domain.SlackEscape(s)
			if strings.ContainsAny(e, "<>") || slackUnescape.Replace(e) != s {
				t.Fatalf("SlackEscape(%q) = %q", s, e)
			}
		}
		got := domain.SlackText(title, body, link)
		wantLinks := 0
		if link != "" {
			wantLinks = 1
			suffix := "\n<" + domain.SlackEscape(link) + "|Open in PantherClaw>"
			if !strings.HasSuffix(got, suffix) {
				t.Fatalf("the link is not the message's last line: %q", got)
			}
		}
		if strings.Count(got, "<") != wantLinks || strings.Count(got, ">") != wantLinks {
			t.Fatalf("the Slack text %q has markup beyond the one link", got)
		}
		if !strings.HasPrefix(got, "*"+domain.SlackEscape(title)+"*\n"+domain.SlackEscape(body)) {
			t.Fatalf("the Slack text %q is not the escaped title and body", got)
		}
	})
}
