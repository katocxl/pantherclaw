// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"encoding/json/v2"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/browsercompare"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// withBrowser makes the connection a kind-local connection serving
// pc.browser (the managed extension through pclaw browser host).
func withBrowser(h *harness) {
	h.pkgFile = "../../packages/pc-browser/package.yaml"
	h.conn.Kind, h.conn.GatewayConnection.Package, h.conn.AccessMode = "local", "pc.browser", "none"
}

func browserCall(tool string, input map[string]any) string {
	b, _ := json.Marshal(map[string]any{"tool": tool, "input": input})
	return string(b)
}

func submit(secret any) string {
	in := map[string]any{
		"url": "https://shop.example.com/login", "page_url": "https://shop.example.com/", "method": "post",
		"fields": []string{"user", "password"}, "call": "c1",
	}
	if secret != nil {
		in["secret_fields"] = secret
	}
	return browserCall("browser_submit", in)
}

// TestHR747_ASecretFieldSubmitIsRefusedBeforeTheAuthority: a form submit
// with secret_fields true is refused at the gateway with
// BROWSER_SECRET_FIELD and the agent-safe reason (a person takes over the
// tab), reported as a local refusal; the Authority is never asked, so no
// grant, policy or approval changes it.
func TestHR747_ASecretFieldSubmitIsRefusedBeforeTheAuthority(t *testing.T) {
	for name, opt := range map[string]func(*harness){
		"allowing authority": func(*harness) {},
		"monitor mode": func(h *harness) {
			h.auth.mode = pb.DispatchMode_DISPATCH_MODE_MONITOR
		},
	} {
		h := setup(t, withBrowser, opt)
		r := h.hook(t, submit(true), nil)
		s := h.auth.snap()
		if r.code != http.StatusOK || r.answer.Decision != "deny" || r.answer.Code != dispatch.CodeBrowserSecretField ||
			r.answer.ErrorClass != string(dispatch.CannotAuthorize) || !strings.HasPrefix(r.answer.Reason, dispatch.BrowserSecretFieldReason) ||
			r.answer.Held || s.authorize != 0 || len(s.begins) != 0 || len(s.records) != 0 {
			t.Fatalf("%s: %d %+v, authorize %d", name, r.code, r.answer, s.authorize)
		}
		refusals := h.localRefusals()
		if len(refusals) != 1 || !strings.Contains(refusals[0], " browser_secret_field browser.form.submit ") {
			t.Fatalf("%s: refusals %v", name, refusals)
		}
		for _, w := range []string{"password", "one-time-code", "payment", "take over this tab", "continue after"} {
			if !strings.Contains(r.answer.Reason, w) {
				t.Errorf("%s: the reason does not say %q: %q", name, w, r.answer.Reason)
			}
		}
	}
}

// TestHR747_ASubmitWithoutSecretFieldsIsDecided: secret_fields false goes
// to the Authority and is answered as decided; a submit without
// secret_fields (it is required) never reaches the Authority either.
func TestHR747_ASubmitWithoutSecretFieldsIsDecided(t *testing.T) {
	h := setup(t, withBrowser)
	r := h.hook(t, submit(false), nil)
	s := h.auth.snap()
	if r.answer.Decision != "allow" || s.authorize != 1 || len(h.localRefusals()) != 0 || s.outcome() != pb.Outcome_OUTCOME_DELEGATED {
		t.Fatalf("not secret: %+v, authorize %d, refusals %v", r.answer, s.authorize, h.localRefusals())
	}
	if a := s.actions[0].Action; a.Operation != "browser.form.submit" || a.Target.ID != "shop.example.com" ||
		strings.Contains(string(a.Params), "hunter2") {
		t.Fatalf("mapped %+v", a)
	}

	h = setup(t, withBrowser)
	r = h.hook(t, submit(nil), nil)
	if r.answer.Decision != "deny" || h.auth.snap().authorize != 0 {
		t.Fatalf("no secret_fields: %+v", r.answer)
	}
}

// fakeComparer records the compare jobs the hook face queues.
type fakeComparer struct {
	mu   sync.Mutex
	jobs []browsercompare.Job
}

func (f *fakeComparer) Enqueue(j browsercompare.Job) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs = append(f.jobs, j)
	return true
}

func (f *fakeComparer) all() []browsercompare.Job {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]browsercompare.Job(nil), f.jobs...)
}

func navigateCall(url string) string {
	return browserCall("browser_navigate", map[string]any{"url": url, "user_agent": "AgentBrowser/1.0", "accept_language": "en", "call": "c1"})
}

// TestHR759_AnAllowedNavigationToACompareSiteIsQueued: the hook face
// queues an allowed browser.navigate whose host is a compare site, with
// the normalized url and the agent's headers, after the answer, and the
// answer is the same as without the compare.
func TestHR759_AnAllowedNavigationToACompareSiteIsQueued(t *testing.T) {
	fc := &fakeComparer{}
	h := setup(t, withBrowser, func(h *harness) {
		h.compare = fc
		h.compareSites = []browsercompare.Site{{Host: "news.example.com", IncludeSubdomains: true}}
	})
	r := h.hook(t, navigateCall("HTTPS://EU.News.Example.com:443/a?b=1#x"), nil)
	if r.answer.Decision != "allow" {
		t.Fatalf("answer %+v", r.answer)
	}
	jobs := fc.all()
	if len(jobs) != 1 {
		t.Fatalf("jobs %+v", jobs)
	}
	j := jobs[0]
	if j.URL != "https://eu.news.example.com/a?b=1" || j.Host != "eu.news.example.com" || j.Connection != connID ||
		j.UserAgent != "AgentBrowser/1.0" || j.AcceptLanguage != "en" || j.Transaction != r.answer.TransactionID {
		t.Fatalf("job %+v", j)
	}
}

// TestHR759_NothingElseIsCompared: a denied or held navigation, a
// navigation to a site not marked, and another operation are not queued,
// and the answer does not change.
func TestHR759_NothingElseIsCompared(t *testing.T) {
	sites := []browsercompare.Site{{Host: "news.example.com"}}
	for name, tc := range map[string]struct {
		opt  func(*harness)
		body string
		want string
	}{
		"denied":    {func(h *harness) { h.auth.decision = pb.Decision_DECISION_DENY }, navigateCall("https://news.example.com/"), "deny"},
		"held":      {func(h *harness) { h.auth.decision = pb.Decision_DECISION_REQUIRE_APPROVAL }, navigateCall("https://news.example.com/"), "deny"},
		"unmarked":  {func(*harness) {}, navigateCall("https://other.example.com/"), "allow"},
		"subdomain": {func(*harness) {}, navigateCall("https://eu.news.example.com/"), "allow"},
		"download": {func(*harness) {}, browserCall("browser_download", map[string]any{
			"url": "https://news.example.com/f.pdf", "call": "c1",
		}), "allow"},
	} {
		fc := &fakeComparer{}
		h := setup(t, withBrowser, tc.opt, func(h *harness) { h.compare, h.compareSites = fc, sites })
		if r := h.hook(t, tc.body, nil); r.answer.Decision != tc.want {
			t.Errorf("%s: %+v", name, r.answer)
		}
		if jobs := fc.all(); len(jobs) != 0 {
			t.Errorf("%s: queued %+v", name, jobs)
		}
	}
}
