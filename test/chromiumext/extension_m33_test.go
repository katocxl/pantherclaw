// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package chromiumext checks the managed browser extension
// (integrations/chromium-extension, G0 M33 D980–D982) against its
// contract: the manifest, what it sends, and that it fails closed. The
// checks read the sources; where node is on PATH they also run the
// extension's own scripts against small browser stand-ins. The extension's
// own test suite, with its package.json and CI, comes later.
package chromiumext

import (
	"encoding/json/v2"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const extDir = "../../integrations/chromium-extension/extension"

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(extDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// sources is the extension's script sources by file name.
type sources map[string]string

func load(t *testing.T) sources {
	t.Helper()
	s := sources{}
	for _, f := range []string{"manifest.json", "managed_schema.json", "background.js", "host.js", "hold.js", "content.js", "fields.js", "rules.js", "popup.js"} {
		s[f] = read(t, f)
	}
	return s
}

func (s sources) with(file, old, replacement string) sources {
	c := sources{}
	for k, v := range s {
		c[k] = v
	}
	c[file] = strings.Replace(c[file], old, replacement, 1)
	return c
}

// ordered reports whether each of parts occurs in src after the one
// before it.
func ordered(src string, parts ...string) bool {
	at := 0
	for _, p := range parts {
		i := strings.Index(src[at:], p)
		if i < 0 {
			return false
		}
		at += i + len(p)
	}
	return true
}

// failClosed lists what in the sources breaks HR-751.
func failClosed(s sources) []string {
	var bad []string
	need := func(ok bool, what string) {
		if !ok {
			bad = append(bad, what)
		}
	}
	host, bg, hold, content, rules := s["host.js"], s["background.js"], s["hold.js"], s["content.js"], s["rules.js"]
	need(strings.Contains(host, `return { decision: "deny", held: false, code: CANNOT_DECIDE, reason, transaction_id: "" };`),
		"host.js: cannotDecide is a deny with CANNOT_DECIDE")
	need(ordered(host, "if (!port) {", "return Promise.resolve(fallback);"), "host.js: no port answers the fallback")
	need(ordered(host, "port.onDisconnect.addListener", "p.resolve(p.fallback);"), "host.js: a disconnect answers the fallback")
	need(ordered(host, "const timer = setTimeout(() => {", "resolve(fallback);", "ANSWER_TIMEOUT_MS"), "host.js: no answer in time is the fallback")
	need(ordered(host, `if (a === fallback || (a.decision !== "allow" && a.decision !== "deny")) {`, "return fallback;"),
		"host.js: an answer that is not allow or deny is the fallback")
	need(strings.Contains(host, "MAX_BACKOFF_MS = 30_000"), "host.js: reconnect backoff of at most 30 s")
	// Downloads: paused at once, resumed only on allow, otherwise canceled, removed and erased.
	need(ordered(bg, "async function onDownload", "chrome.downloads.pause(item.id)", `if (answer.decision === "allow") {`,
		"chrome.downloads.resume(item.id)", "return;", "chrome.downloads.cancel(item.id)", "chrome.downloads.removeFile(item.id)",
		"chrome.downloads.erase({ id: item.id })"), "background.js: a download not allowed is canceled, its file removed and its entry erased")
	need(strings.Count(bg, "chrome.downloads.resume(") == 2, "background.js: a download resumes only on allow or in a takeover")
	need(ordered(bg, "async function decideNavigate", `if (answer.decision === "allow") {`, "allowNavigationOnce(tabId,"),
		"background.js: a navigation is let through only on allow")
	need(strings.Count(bg, "allowNavigationOnce(") == 2, "background.js: allowNavigationOnce only after an allow (navigate, submit)")
	need(ordered(bg, "async function decideSubmit", "if (input.secret_fields) {", `return { ...answer, decision: "deny" };`),
		"background.js: a submit with a secret field is denied whatever the answer")
	need(strings.Contains(bg, `reply.then(sendResponse, () => sendResponse(cannotDecide()));`), "background.js: a failed decision answers cannot decide")
	// The hold page: opened only on allow, asked again every 10 s for 30 min while held, otherwise it stays.
	need(ordered(hold, `if (a && a.decision === "allow") {`, "location.replace(url);"), "hold.js: the page opens only on allow")
	need(strings.Count(hold, "location.replace(") == 1, "hold.js: one way to open the page")
	need(strings.Contains(hold, "RETRY_MS = 10_000") && strings.Contains(hold, "WAIT_MS = 30 * 60_000"), "hold.js: asks again every 10 s for 30 min")
	need(ordered(hold, "if (a && a.held && Date.now() - started + RETRY_MS <= WAIT_MS) {", "continue;"), "hold.js: only a hold asks again")
	need(strings.Contains(hold, `show("PantherClaw cannot decide"`), `hold.js: says "PantherClaw cannot decide"`)
	need(ordered(hold, `const key = "nav:" + tab.id + ":" + url;`, "...ids"), "hold.js: the same call and action id while held")
	need(strings.Contains(hold, "MAX_URL = 1800") && strings.Contains(bg, "MAX_URL = 1800"), "a URL over 1800 characters is refused locally")
	// Submits and marked clicks happen only on allow.
	need(ordered(content, `if (a.decision !== "allow" || info.secret_fields || !form.isConnected) {`, "return;", "form.requestSubmit("),
		"content.js: a submit happens only on allow and never with a secret field")
	need(ordered(content, `if (a.decision === "allow" && marked.isConnected) {`, "marked.click();"), "content.js: a marked click happens only on allow")
	need(ordered(content, `return a && typeof a.decision === "string" ? a : { decision: "deny" };`, `return { decision: "deny" };`),
		"content.js: no answer is a deny")
	// Every top-level navigation goes to the hold page; a decided one passes once, on its tab.
	need(ordered(rules, `regexSubstitution: `+"`chrome-extension://${chrome.runtime.id}/hold.html#\\\\0`", `regexFilter: "^https?://.*$"`, `"main_frame"`),
		"rules.js: the hold rule redirects every top-level http(s) navigation")
	need(ordered(rules, "export function allowNavigationOnce", "tabIds: [tabId]", "NAVIGATION_RULE_TTL_MS"), "rules.js: a decided navigation passes once on its tab")
	// A decided navigation's or submit's rule lasts at most 10 s and goes once its request redirects, completes or fails.
	need(strings.Contains(rules, "const NAVIGATION_RULE_TTL_MS = 10_000;"), "rules.js: a decided rule lasts at most 10 s")
	need(ordered(bg, "[chrome.webRequest.onBeforeRedirect, chrome.webRequest.onCompleted, chrome.webRequest.onErrorOccurred]",
		"void removeNavigationRulesFor(d.tabId, d.url);", `types: ["main_frame"]`), "background.js: a decided rule goes once its request completes or fails")
	// A download is a takeover tab's only when no other open tab shows its page.
	need(ordered(bg, "async function fromTakeoverTab", "if (!tab || tab.url !== item.referrer) {", "chrome.tabs.query({})",
		"return tabs !== null && tabs.every((t) => t.id === tabId || t.url !== item.referrer);"),
		"background.js: a download counts as the takeover tab's only when no other tab shows its page")
	return bad
}

// TestHR751_TheExtensionFailsClosed: with no port, a disconnect, no
// answer or a deny, nothing happens: the navigation stays on the hold page,
// the download is canceled, removed and erased, and the submit or click
// does not happen. A copy of the sources that resumes a denied download,
// or opens a page on a deny, fails the check.
func TestHR751_TheExtensionFailsClosed(t *testing.T) {
	s := load(t)
	if bad := failClosed(s); len(bad) > 0 {
		t.Fatalf("the extension does not fail closed:\n%s", strings.Join(bad, "\n"))
	}
	for name, mutated := range map[string]sources{
		"resume on deny": s.with("background.js", "await chrome.downloads.cancel(item.id)", "await chrome.downloads.resume(item.id)"),
		"open on deny":   s.with("hold.js", `if (a && a.decision === "allow") {`, `if (a) {`),
		"click on deny":  s.with("content.js", `if (a.decision === "allow" && marked.isConnected) {`, `if (marked.isConnected) {`),
		"allow on fail":  s.with("host.js", `return { decision: "deny", held: false, code: CANNOT_DECIDE`, `return { decision: "allow", held: false, code: CANNOT_DECIDE`),
		"shared page":    s.with("background.js", "tabs.every((t) => t.id === tabId || t.url !== item.referrer)", "true"),
		"long rule":      s.with("rules.js", "const NAVIGATION_RULE_TTL_MS = 10_000;", "const NAVIGATION_RULE_TTL_MS = 60_000;"),
		"rule kept":      s.with("background.js", "void removeNavigationRulesFor(d.tabId, d.url);", ""),
	} {
		if len(failClosed(mutated)) == 0 {
			t.Errorf("%s: the check passes a source that does not fail closed", name)
		}
	}
	t.Run("node", func(t *testing.T) {
		if !haveNode() {
			t.Skip("node not found")
		}
		out := runNode(t, hostScript)
		for _, want := range []string{"no-port deny CANNOT_DECIDE", "allow allow t", "held deny true", "odd deny CANNOT_DECIDE", "disconnect deny CANNOT_DECIDE"} {
			if !strings.Contains(out, want+"\n") {
				t.Errorf("host.js run lacks %q:\n%s", want, out)
			}
		}
	})
}

// TestHR751_TakeoverDownloadsAndDecidedRulesStayNarrow: run by node
// against a stand-in browser, a download whose page is open only in the
// takeover tab is saved without asking, and one whose page is also open in
// another tab is asked and, without an answer, canceled and erased; a
// decided navigation's or submit's rule lasts 10 s and goes once a request
// it matches on its tab completes or fails, and not for another address or
// tab; when the worker starts, every one-navigation rule a stopped worker
// left goes, and the takeover rules stay (D1221a R4).
func TestHR751_TakeoverDownloadsAndDecidedRulesStayNarrow(t *testing.T) {
	if !haveNode() {
		t.Skip("node not found")
	}
	out := runNode(t, backgroundScript)
	for _, want := range []string{
		"download only-tab resume 1", "download shared-page cancel 2,erase 2", "download other-page cancel 3,erase 3",
		"worker start rules 901", "rule ttl 10000", "rules other-address 7,8", "rules completed 8", "rules errored none",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("background.js run lacks %q:\n%s", want, out)
		}
	}
}

// d974Inputs are the keys of each tool's input (D974).
var d974Inputs = map[string][]string{
	"requestTakeover": {"call", "minutes", "page_url"},
	"decideNavigate":  {"accept_language", "call", "url", "user_agent"},
	"decideSubmit":    {"call", "fields", "method", "page_url", "secret_fields", "url"},
	"decideClick":     {"call", "label", "page_url", "selector"},
	"onDownload":      {"call", "filename", "mime", "page_url", "url"},
}

// inputKeys returns the keys of the `const input = {…}` object literal in
// the function fn of src.
func inputKeys(src, fn string) ([]string, error) {
	i := strings.Index(src, "function "+fn+"(")
	if i < 0 {
		return nil, fmt.Errorf("no function %s", fn)
	}
	j := strings.Index(src[i:], "const input = {")
	if j < 0 {
		return nil, fmt.Errorf("%s builds no input", fn)
	}
	body := src[i+j+len("const input = {"):]
	var keys []string
	depth, start := 0, 0
	for k := 0; k < len(body); k++ {
		switch body[k] {
		case '(', '[', '{':
			depth++
		case ')', ']':
			depth--
		case '}':
			if depth == 0 {
				return append(keys, key(body[start:k])...), nil
			}
			depth--
		case ',':
			if depth == 0 {
				keys = append(keys, key(body[start:k])...)
				start = k + 1
			}
		}
	}
	return nil, fmt.Errorf("%s: unterminated input", fn)
}

func key(entry string) []string {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil
	}
	k, _, _ := strings.Cut(entry, ":")
	return []string{strings.TrimSpace(k)}
}

var forbiddenAPIs = []string{
	"captureVisibleTab", "tabCapture", "desktopCapture", "pageCapture", "chrome.debugger", "chrome.scripting",
	"outerHTML", "innerHTML", "document.body", "getSelection", "chrome.cookies", "chrome.history", "fetch(", "XMLHttpRequest", "WebSocket",
}

// pageContent lists what in the sources lets page content out (HR-754).
func pageContent(s sources) []string {
	var bad []string
	bg, host := s["background.js"], s["host.js"]
	for fn, want := range d974Inputs {
		got, err := inputKeys(bg, fn)
		slices.Sort(got)
		if err != nil || !slices.Equal(got, want) {
			bad = append(bad, fmt.Sprintf("background.js %s sends %v (%v), want %v", fn, got, err, want))
		}
	}
	if !strings.Contains(bg, "input.bytes = item.totalBytes;") || strings.Count(bg, "input.") != strings.Count(bg, "input.bytes")+strings.Count(bg, "input.secret_fields")+strings.Count(bg, "input.url") {
		bad = append(bad, "background.js adds to an input beyond a download's bytes")
	}
	decides := regexp.MustCompile(`host\.decide\("([a-z_]+)", input, `).FindAllStringSubmatch(bg, -1)
	var tools []string
	for _, d := range decides {
		tools = append(tools, d[1])
	}
	slices.Sort(tools)
	if want := []string{"browser_click", "browser_download", "browser_navigate", "browser_submit", "browser_takeover"}; !slices.Equal(tools, want) ||
		strings.Count(bg, "host.decide(") != len(want) {
		bad = append(bad, fmt.Sprintf("background.js asks %v, want each D974 tool once with its input", tools))
	}
	if !strings.Contains(host, `this.ask({ type: "decide", tool, action_id: actionId, input }, fallback)`) || strings.Count(host, "postMessage(") != 1 ||
		!strings.Contains(host, "port.postMessage({ v: 1, id, ...body });") {
		bad = append(bad, "host.js sends more than the decide message")
	}
	for _, f := range []string{"background.js", "host.js", "hold.js", "content.js", "rules.js", "popup.js", "fields.js"} {
		for _, api := range forbiddenAPIs {
			if strings.Contains(s[f], api) {
				bad = append(bad, f+" uses "+api)
			}
		}
	}
	// Field values: only fields.js reads them (to refuse and clear secret input); nothing that sends reads one.
	for _, f := range []string{"background.js", "host.js", "hold.js", "content.js"} {
		if strings.Contains(s[f], ".value") {
			bad = append(bad, f+" reads a field value")
		}
	}
	if !strings.Contains(s["content.js"], "return { url: action, page_url: location.href, method, fields, secret_fields: pcFields.formHasSecretValue(form) };") {
		bad = append(bad, "content.js describes a submit beyond its address, method, field names and secret_fields")
	}
	return bad
}

// TestHR754_NoPageContentLeavesTheBrowser: the extension sends only the
// D974 inputs of each tool, through the one decide message of host.js; it
// uses no capture, DOM-dump, cookie, history or network API, and nothing
// that sends reads a field value. A copy that adds page text to a
// navigation, or reads a field value in the content script, fails.
func TestHR754_NoPageContentLeavesTheBrowser(t *testing.T) {
	s := load(t)
	if bad := pageContent(s); len(bad) > 0 {
		t.Fatalf("page content can leave the browser:\n%s", strings.Join(bad, "\n"))
	}
	for name, mutated := range map[string]sources{
		"page text":   s.with("background.js", `url, user_agent: String(m.user_agent || ""),`, `url, text: String(m.text || ""), user_agent: String(m.user_agent || ""),`),
		"field value": s.with("content.js", "const name = /** @type {HTMLInputElement} */ (el).name;", "const name = /** @type {HTMLInputElement} */ (el).value;"),
		"screenshot":  s.with("background.js", "async function onDownload", "chrome.tabs.captureVisibleTab();\nasync function onDownload"),
	} {
		if len(pageContent(mutated)) == 0 {
			t.Errorf("%s: the check passes a source that sends page content", name)
		}
	}
	t.Run("node", func(t *testing.T) {
		if !haveNode() {
			t.Skip("node not found")
		}
		if out := runNode(t, hostScript); !strings.Contains(out, "sent v,id,type,tool,action_id,input\n") {
			t.Errorf("host.js sends other members:\n%s", out)
		}
	})
}

var (
	secretTokens = []string{
		"current-password", "new-password", "one-time-code", "cc-name", "cc-given-name", "cc-additional-name",
		"cc-family-name", "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc", "cc-type",
	}
	paymentHosts   = []string{"js.stripe.com", "checkout.stripe.com", "*.braintreegateway.com", "*.adyen.com", "*.paypal.com", "pay.google.com"}
	challengeHosts = []string{"www.recaptcha.net", "*.hcaptcha.com", "challenges.cloudflare.com", "*.arkoselabs.com", "*.funcaptcha.com"}
	secretPattern  = `/(pass(word|wd|code)?|\bpin\b|otp|one.?time|cvv|cvc|csc|security.?code|card.?(number|no|num)|\bcc.?num|iban|routing.?number|account.?number|\bssn\b)/i`
)

// secretFields lists what in the sources breaks HR-752.
func secretFields(s sources) []string {
	var bad []string
	f := s["fields.js"]
	for _, tok := range secretTokens {
		if !strings.Contains(f, `"`+tok+`"`) {
			bad = append(bad, "fields.js lacks the autocomplete token "+tok)
		}
	}
	for _, h := range append(slices.Clone(paymentHosts), challengeHosts...) {
		if !strings.Contains(f, `"`+h+`"`) {
			bad = append(bad, "fields.js lacks the host "+h)
		}
	}
	if !strings.Contains(f, secretPattern) {
		bad = append(bad, "fields.js lacks the name pattern")
	}
	if !strings.Contains(f, `host === "www.google.com" && location.pathname.startsWith("/recaptcha/")`) {
		bad = append(bad, "fields.js lacks the reCAPTCHA path")
	}
	if !strings.Contains(f, `el.type === "password"`) {
		bad = append(bad, "fields.js does not refuse password inputs")
	}
	// A field once seen as secret stays secret, and an input whose type leaves "password" is kept as secret.
	if !ordered(f, "const seenSecret = new WeakSet();", "if (seenSecret.has(field)) {", "return true;", "seenSecret.add(field);",
		`(r.oldValue || "").toLowerCase() === "password"`, "seenSecret.add(r.target);", `attributeFilter: ["type"], attributeOldValue: true`) {
		bad = append(bad, "fields.js lets a field stop being secret when its type changes")
	}
	// A field that replaces a removed secret input is secret (D1221a R3).
	if !ordered(f, "const replaced = [];", "replaced.push({", "if (replaced.some((d) => takesPlace(el, d))) {", "seenSecret.add(el);",
		"childList: true,") {
		bad = append(bad, "fields.js lets a script swap a secret input for a plain one")
	}
	if !ordered(f, "el instanceof HTMLTextAreaElement", "isContentEditable", `[el.getAttribute("name"), el.id, el.getAttribute("aria-label")]`) {
		bad = append(bad, "fields.js does not refuse secret text areas and contenteditable fields")
	}
	if !ordered(f, `for (const type of ["beforeinput", "paste", "drop", "keydown"]) {`, "window.addEventListener(type, onEdit, opts);",
		`for (const type of ["input", "change"]) {`, "window.addEventListener(type, onValue, opts);") || !strings.Contains(f, "const opts = { capture: true };") {
		bad = append(bad, "fields.js does not refuse typing, pasting and dropping, and clear a value, in the capture phase")
	}
	if !ordered(f, `if (input.value !== "") {`, `input.value = "";`) {
		bad = append(bad, "fields.js does not clear a value that arrived")
	}
	if !ordered(f, "if (challengeFrame()) {", `"pointerdown"`, `"keydown"`, `"input"`, "window.addEventListener(type, onChallenge, opts);") {
		bad = append(bad, "fields.js does not refuse every pointer, key and input event in a challenge frame")
	}
	// The managed configuration only adds hosts; nothing removes a built-in one.
	if !ordered(f, `chrome.storage.managed.get(["extra_secret_hosts"]`, "extraHosts = ") || strings.Contains(f, "PAYMENT_HOSTS =") && strings.Count(f, "PAYMENT_HOSTS") != 2 ||
		strings.Count(f, "CHALLENGE_HOSTS") != 2 || strings.Count(f, "lifted = false") != 2 || strings.Count(f, "lifted = true") != 1 {
		bad = append(bad, "fields.js lets something other than a takeover lift the refusal or remove a built-in host")
	}
	var schema struct {
		Properties map[string]struct {
			Type  string `json:"type"`
			Items struct {
				Type string `json:"type"`
			} `json:"items"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(s["managed_schema.json"]), &schema); err != nil {
		bad = append(bad, "managed_schema.json: "+err.Error())
	}
	keys := make([]string, 0, len(schema.Properties))
	for k := range schema.Properties {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if p := schema.Properties["extra_secret_hosts"]; !slices.Equal(keys, []string{"click_rules", "extra_secret_hosts", "host_name"}) || p.Type != "array" || p.Items.Type != "string" {
		bad = append(bad, fmt.Sprintf("managed_schema.json offers %v; only host_name, click_rules and the additive extra_secret_hosts", keys))
	}
	// A submit with a secret value is refused locally and still asked.
	if !ordered(s["content.js"], "if (info.secret_fields) {", "pcFields.showBanner(pcFields.notice);", `void ask({ type: "submit", ...info })`) {
		bad = append(bad, "content.js does not ask a secret submit with secret_fields")
	}
	return bad
}

// TestHR752_SecretAndChallengeFieldsAreRefused: fields.js names every
// listed autocomplete token, the name pattern and the payment and
// challenge hosts, refuses typing, pasting and dropping into a secret
// input and clears a value that arrives, refuses every event in a
// challenge frame, and only a takeover lifts it; the managed configuration
// can only add hosts. Run by node, a password, one-time-code or card input
// is refused and an e-mail input is not. A copy without the card number
// token, or with a schema member that drops built-in hosts, fails.
func TestHR752_SecretAndChallengeFieldsAreRefused(t *testing.T) {
	s := load(t)
	if bad := secretFields(s); len(bad) > 0 {
		t.Fatalf("secret fields:\n%s", strings.Join(bad, "\n"))
	}
	for name, mutated := range map[string]sources{
		"no cc-number":  s.with("fields.js", `"cc-number", `, ""),
		"no paypal":     s.with("fields.js", `"*.paypal.com", `, ""),
		"bubble phase":  s.with("fields.js", "const opts = { capture: true };", "const opts = { capture: false };"),
		"removal knob":  s.with("managed_schema.json", `"extra_secret_hosts": {`, `"disable_secret_hosts": {"type": "boolean"}, "extra_secret_hosts": {`),
		"other lifter":  s.with("fields.js", "let lifted = false;", "let lifted = false;\n  window.addEventListener(\"message\", () => { lifted = true; });"),
		"secret submit": s.with("content.js", "if (info.secret_fields) {", "if (false) {"),
		"not sticky":    s.with("fields.js", "if (seenSecret.has(field)) {", "if (false) {"),
		"inputs only":   s.with("fields.js", "el instanceof HTMLTextAreaElement", "false"),
		"no swaps":      s.with("fields.js", "childList: true, ", ""),
	} {
		if len(secretFields(mutated)) == 0 {
			t.Errorf("%s: the check passes a source that lets secret input through", name)
		}
	}
	t.Run("node", func(t *testing.T) {
		if !haveNode() {
			t.Skip("node not found")
		}
		out := runNode(t, fieldsScript)
		for _, want := range []string{
			"shop.example.com password true", "shop.example.com otp-autocomplete true", "shop.example.com billing-cc-number true",
			"shop.example.com pin-name true", "shop.example.com card-placeholder true", "shop.example.com email false", "shop.example.com div false",
			"shop.example.com beforeinput-secret prevented", "shop.example.com beforeinput-email allowed", "shop.example.com input-secret cleared",
			"shop.example.com input-email kept", "shop.example.com tab-key allowed", "shop.example.com lifted allowed",
			"shop.example.com show-password prevented", "shop.example.com show-password-input cleared", "shop.example.com pwd_field-was-password prevented",
			"shop.example.com pwd_field-text false", "shop.example.com swapped-same-name true", "shop.example.com swapped-same-place true",
			"shop.example.com swapped-elsewhere false", "shop.example.com textarea-cvv true", "shop.example.com textarea-notes false",
			"shop.example.com contenteditable-text-node true", "shop.example.com contenteditable-input cleared",
			"shop.example.com contenteditable-message false", "shop.example.com element-not-editable false",
			"js.stripe.com email true", "x.paypal.com email true", "paypal.com email true", "pay.example.test email true",
			"www.google.com/recaptcha/ click prevented", "challenges.cloudflare.com keydown prevented", "shop.example.com click none",
		} {
			if !strings.Contains(out, want+"\n") {
				t.Errorf("fields.js run lacks %q:\n%s", want, out)
			}
		}
	})
}

// TestHR751_TheManifestKeepsTheAgentInTheDecidedBrowser: the manifest asks
// exactly the D980 permissions, no capture or debugger permission, runs
// fields.js before content.js in every frame at document start, and is not
// allowed in incognito.
func TestHR751_TheManifestKeepsTheAgentInTheDecidedBrowser(t *testing.T) {
	check := func(raw string) []string {
		var m struct {
			Version        int      `json:"manifest_version"`
			MinChrome      string   `json:"minimum_chrome_version"`
			Permissions    []string `json:"permissions"`
			Hosts          []string `json:"host_permissions"`
			Incognito      string   `json:"incognito"`
			ContentScripts []struct {
				JS        []string `json:"js"`
				AllFrames bool     `json:"all_frames"`
				Blank     bool     `json:"match_about_blank"`
				Fallback  bool     `json:"match_origin_as_fallback"`
				RunAt     string   `json:"run_at"`
			} `json:"content_scripts"`
			Background struct {
				Type string `json:"type"`
			} `json:"background"`
			Externally any `json:"externally_connectable"`
		}
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			return []string{err.Error()}
		}
		var bad []string
		want := []string{"alarms", "declarativeNetRequestWithHostAccess", "downloads", "nativeMessaging", "storage", "tabs", "webNavigation", "webRequest"}
		got := slices.Sorted(slices.Values(m.Permissions))
		if !slices.Equal(got, want) {
			bad = append(bad, fmt.Sprintf("permissions %v, want %v", got, want))
		}
		if m.Version != 3 || m.MinChrome != "120" || m.Incognito != "not_allowed" || m.Background.Type != "module" || m.Externally != nil ||
			!slices.Equal(m.Hosts, []string{"http://*/*", "https://*/*"}) {
			bad = append(bad, fmt.Sprintf("manifest %+v", m))
		}
		if len(m.ContentScripts) != 1 || !slices.Equal(m.ContentScripts[0].JS, []string{"fields.js", "content.js"}) || !m.ContentScripts[0].AllFrames ||
			!m.ContentScripts[0].Blank || !m.ContentScripts[0].Fallback || m.ContentScripts[0].RunAt != "document_start" {
			bad = append(bad, fmt.Sprintf("content scripts %+v", m.ContentScripts))
		}
		return bad
	}
	raw := read(t, "manifest.json")
	if bad := check(raw); len(bad) > 0 {
		t.Fatalf("manifest:\n%s", strings.Join(bad, "\n"))
	}
	for name, mutated := range map[string]string{
		"debugger":  strings.Replace(raw, `"alarms"`, `"alarms", "debugger"`, 1),
		"incognito": strings.Replace(raw, `"incognito": "not_allowed"`, `"incognito": "spanning"`, 1),
		"top only":  strings.Replace(raw, `"all_frames": true`, `"all_frames": false`, 1),
	} {
		if len(check(mutated)) == 0 {
			t.Errorf("%s: the check passes", name)
		}
	}
}

func haveNode() bool {
	_, err := exec.LookPath("node")
	return err == nil
}

// runNode runs a node script with the extension directory as its argument.
func runNode(t *testing.T, script string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "run.mjs")
	if err := os.WriteFile(p, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.Abs(extDir)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), "node", p, dir).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	return strings.ReplaceAll(string(out), "\r\n", "\n")
}

// hostScript runs host.js's Host against stand-in native ports.
const hostScript = `
import { pathToFileURL } from "node:url";
import path from "node:path";
const dir = process.argv[2];
let port = null;
let sent = null;
globalThis.chrome = { runtime: { lastError: undefined, connectNative() { if (!port) throw new Error("no host"); return port; } } };
const { Host } = await import(pathToFileURL(path.join(dir, "host.js")).href);
function fakePort(answer) {
  const msg = [], disc = [];
  return {
    onMessage: { addListener: (f) => msg.push(f) },
    onDisconnect: { addListener: (f) => disc.push(f) },
    postMessage(m) {
      sent = m;
      if (answer === "disconnect") { setTimeout(() => disc.forEach((f) => f()), 5); return; }
      setTimeout(() => msg.forEach((f) => f({ v: 1, id: m.id, ...answer })), 5);
    },
  };
}
async function one(label, answer) {
  port = answer === undefined ? null : fakePort(answer);
  const h = new Host(async () => "dev.pantherclaw.browser");
  await h.connect();
  const a = await h.decide("browser_navigate", { url: "https://docs.example.com/", call: "c" }, "a1");
  console.log(label, a.decision, label === "held" ? String(a.held) : (a.code || a.transaction_id));
  if (h.retry) clearTimeout(h.retry);
}
await one("no-port", undefined);
await one("allow", { decision: "allow", held: false, code: "", reason: "", transaction_id: "t" });
await one("held", { decision: "deny", held: true, code: "", reason: "", transaction_id: "t" });
await one("odd", { decision: "maybe" });
await one("disconnect", "disconnect");
port = fakePort({ decision: "allow" });
const h = new Host(async () => "x");
await h.connect();
await h.decide("browser_navigate", { url: "https://docs.example.com/" }, "a1");
console.log("sent " + Object.keys(sent).join(","));
process.exit(0);
`

// fieldsScript runs fields.js in stand-in frames.
const fieldsScript = `
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
const src = fs.readFileSync(path.join(process.argv[2], "fields.js"), "utf8");
class HTMLElement {
  constructor(a = {}) {
    this.id = a.id || ""; this.attrs = a.attrs || {}; this.isContentEditable = !!a.editable;
    this.parentElement = a.parent || null; this.textContent = a.text || "";
  }
  getAttribute(n) { return n in this.attrs ? this.attrs[n] : null; }
}
class HTMLInputElement extends HTMLElement {
  constructor(a) { super(a); this.type = a.type || "text"; this.name = a.name || ""; this.value = a.value || ""; }
}
class HTMLTextAreaElement extends HTMLElement {
  constructor(a) { super(a); this.value = a.value || ""; }
}
class Text { constructor(parent) { this.parentElement = parent; } }
class KeyboardEvent { constructor(key) { this.key = key; this.ctrlKey = this.metaKey = this.altKey = false; } }
function frame(host, pathname = "/") {
  const listeners = {};
  const observers = [];
  class MutationObserver { constructor(cb) { observers.push(cb); } observe() {} }
  const ctx = {
    HTMLElement, HTMLInputElement, HTMLTextAreaElement, Text, MutationObserver, KeyboardEvent, location: { hostname: host, pathname },
    window: { addEventListener: (t, f) => (listeners[t] ||= []).push(f) },
    document: { documentElement: null },
    chrome: { storage: { managed: { get: (_k, cb) => cb({ extra_secret_hosts: ["pay.example.test"] }) } } },
  };
  ctx.globalThis = ctx;
  vm.runInNewContext(src, ctx);
  const fire = (type, target, ev = {}) => {
    const e = Object.assign(ev, { target, composedPath: () => [target], prevented: false, preventDefault() { this.prevented = true; }, stopImmediatePropagation() {} });
    for (const f of listeners[type] || []) f(e);
    return e;
  };
  return { f: ctx.pcFields, fire, listeners, observers };
}
const verdict = (e) => (e.prevented ? "prevented" : "allowed");
const inputs = {
  password: new HTMLInputElement({ type: "password" }),
  "otp-autocomplete": new HTMLInputElement({ attrs: { autocomplete: "section-login one-time-code" } }),
  "billing-cc-number": new HTMLInputElement({ attrs: { autocomplete: "billing cc-number" } }),
  "pin-name": new HTMLInputElement({ name: "pin" }),
  "card-placeholder": new HTMLInputElement({ attrs: { placeholder: "Card number" } }),
  email: new HTMLInputElement({ type: "email", name: "email", attrs: { autocomplete: "email" } }),
};
const shop = frame("shop.example.com");
for (const [k, el] of Object.entries(inputs)) console.log("shop.example.com", k, shop.f.isSecret(el));
console.log("shop.example.com div", shop.f.isSecret({ name: "password" }));
console.log("shop.example.com beforeinput-secret", shop.fire("beforeinput", inputs.password).prevented ? "prevented" : "allowed");
console.log("shop.example.com beforeinput-email", shop.fire("beforeinput", inputs.email).prevented ? "prevented" : "allowed");
console.log("shop.example.com tab-key", shop.fire("keydown", inputs.password, new KeyboardEvent("Tab")).prevented ? "prevented" : "allowed");
const typed = new HTMLInputElement({ type: "password", value: "hunter2" });
shop.fire("input", typed);
console.log("shop.example.com input-secret", typed.value === "" ? "cleared" : "kept");
const mail = new HTMLInputElement({ type: "email", value: "a@example.com" });
shop.fire("input", mail);
console.log("shop.example.com input-email", mail.value === "" ? "cleared" : "kept");
// A show-password button turns a password input into text: it stays secret.
const shown = new HTMLInputElement({ type: "password", name: "pwd_field", attrs: { autocomplete: "off" } });
shop.fire("focusin", shown);
shown.type = "text";
console.log("shop.example.com show-password", verdict(shop.fire("beforeinput", shown)));
shown.value = "hunter2";
shop.fire("input", shown);
console.log("shop.example.com show-password-input", shown.value === "" ? "cleared" : "kept");
// An input never seen whose type left "password" stays secret.
const unseen = new HTMLInputElement({ type: "text", name: "pwd_field", attrs: { autocomplete: "off" } });
for (const cb of shop.observers) cb([{ target: unseen, attributeName: "type", oldValue: "password" }]);
console.log("shop.example.com pwd_field-was-password", verdict(shop.fire("beforeinput", unseen)));
console.log("shop.example.com pwd_field-text", shop.f.isSecret(new HTMLInputElement({ name: "pwd_field", attrs: { autocomplete: "off" } })));
// A script swaps a password input for a text one: a field in its place is
// secret, by form and name or by parent and neighbor; others are not.
const form = new HTMLElement({});
const box = new HTMLElement({});
box.closest = (s) => (s === "form" ? form : null);
const before = new HTMLElement({});
const gone = new HTMLInputElement({ type: "password", name: "pw" });
const sameName = new HTMLInputElement({ name: "pw" });
sameName.closest = box.closest;
for (const cb of shop.observers) cb([{ type: "childList", target: box, removedNodes: [gone], addedNodes: [sameName], previousSibling: before, nextSibling: null }]);
const samePlace = new HTMLInputElement({ name: "x" });
samePlace.parentNode = box; samePlace.previousSibling = before;
const elsewhere = new HTMLInputElement({ name: "q" });
elsewhere.parentNode = new HTMLElement({});
for (const cb of shop.observers) cb([{ type: "childList", target: box, removedNodes: [], addedNodes: [samePlace, elsewhere] }]);
console.log("shop.example.com swapped-same-name", shop.f.isSecret(sameName));
console.log("shop.example.com swapped-same-place", shop.f.isSecret(samePlace));
console.log("shop.example.com swapped-elsewhere", shop.f.isSecret(elsewhere));
console.log("shop.example.com textarea-cvv", shop.f.isSecret(new HTMLTextAreaElement({ attrs: { name: "cvv" } })));
console.log("shop.example.com textarea-notes", shop.f.isSecret(new HTMLTextAreaElement({ attrs: { name: "notes" } })));
const editHost = new HTMLElement({ editable: true, attrs: { "aria-label": "Password" }, text: "hunter2" });
const editChild = new HTMLElement({ editable: true, parent: editHost });
console.log("shop.example.com contenteditable-text-node", shop.f.isSecret(new Text(editChild)));
shop.fire("input", new Text(editChild));
console.log("shop.example.com contenteditable-input", editHost.textContent === "" ? "cleared" : "kept");
console.log("shop.example.com contenteditable-message", shop.f.isSecret(new HTMLElement({ editable: true, attrs: { "aria-label": "Message" }, text: "hi" })));
console.log("shop.example.com element-not-editable", shop.f.isSecret(new HTMLElement({ attrs: { name: "password" } })));
console.log("shop.example.com click", shop.listeners.click ? "listening" : "none");
shop.f.lift();
console.log("shop.example.com lifted", shop.fire("beforeinput", inputs.password).prevented ? "prevented" : "allowed");
shop.f.restore();
for (const host of ["js.stripe.com", "x.paypal.com", "paypal.com", "pay.example.test"]) {
  console.log(host, "email", frame(host).f.isSecret(inputs.email));
}
const rc = frame("www.google.com", "/recaptcha/api2/anchor");
console.log("www.google.com/recaptcha/ click", rc.fire("click", {}).prevented ? "prevented" : "allowed");
const cf = frame("challenges.cloudflare.com");
console.log("challenges.cloudflare.com keydown", cf.fire("keydown", {}, new KeyboardEvent("Enter")).prevented ? "prevented" : "allowed");
`

// backgroundScript runs background.js and rules.js against a stand-in
// browser with no native host.
const backgroundScript = `
import { pathToFileURL } from "node:url";
import path from "node:path";
const dir = process.argv[2];
const ev = () => { const fs = []; return { fs, addListener: (f) => fs.push(f) }; };
const settle = () => new Promise((r) => setTimeout(r, 50));
const log = [];
const session = {};
// What a stopped worker left: a one-navigation rule (priority 2) whose
// timer is gone, and a takeover rule (priority 3).
let sessionRules = [
  { id: 900, priority: 2, action: { type: "allow" }, condition: { regexFilter: "^https://left\\\\.example\\\\.com/", resourceTypes: ["main_frame"], tabIds: [3] } },
  { id: 901, priority: 3, action: { type: "allow" }, condition: { tabIds: [4] } },
];
let openTabs = [];
globalThis.chrome = {
  runtime: { id: "ext", lastError: undefined, connectNative() { throw new Error("no host"); }, onMessage: ev(), onInstalled: ev(), onStartup: ev() },
  storage: {
    managed: { get: async () => ({}) },
    session: {
      get: async (k) => (k === null ? { ...session } : { [k]: session[k] }),
      set: async (o) => void Object.assign(session, o),
      remove: async (k) => void delete session[k],
    },
  },
  downloads: {
    onCreated: ev(), pause: async () => {}, search: async () => [], removeFile: async () => {},
    resume: async (id) => void log.push("resume " + id), cancel: async (id) => void log.push("cancel " + id), erase: async (q) => void log.push("erase " + q.id),
  },
  webNavigation: { onCommitted: ev(), onErrorOccurred: ev() },
  webRequest: { onBeforeRedirect: ev(), onCompleted: ev(), onErrorOccurred: ev() },
  alarms: { onAlarm: ev(), create: async () => {}, clear: async () => {} },
  tabs: {
    onRemoved: ev(), sendMessage: async () => {}, query: async () => openTabs.slice(),
    get: async (id) => { const t = openTabs.find((x) => x.id === id); if (!t) throw new Error("no tab"); return t; },
  },
  declarativeNetRequest: {
    updateDynamicRules: async () => {},
    getSessionRules: async () => sessionRules.slice(),
    updateSessionRules: async (u) => {
      sessionRules = sessionRules.filter((r) => !(u.removeRuleIds || []).includes(r.id)).concat(u.addRules || []);
    },
  },
};
await import(pathToFileURL(path.join(dir, "background.js")).href);
const rules = await import(pathToFileURL(path.join(dir, "rules.js")).href);
await settle();
console.log("worker start rules", sessionRules.map((r) => r.id).join(",") || "none");
sessionRules = [];

const page = "https://docs.example.com/report";
session["takeover:5"] = Date.now() + 60_000;
async function download(label, id, tabs) {
  openTabs = tabs;
  log.length = 0;
  for (const f of chrome.downloads.onCreated.fs) f({ id, referrer: page, url: page + ".pdf", filename: "r.pdf", mime: "application/pdf", totalBytes: 1 });
  await settle();
  console.log("download", label, log.join(","));
}
await download("only-tab", 1, [{ id: 5, url: page }, { id: 6, url: "https://docs.example.com/" }]);
await download("shared-page", 2, [{ id: 5, url: page }, { id: 6, url: page }]);
await download("other-page", 3, [{ id: 5, url: "https://docs.example.com/other" }]);

const re = "^" + rules.re2Escape("https://shop.example.com/pay") + "(\\?.*)?$";
const realSetTimeout = globalThis.setTimeout;
let ttl = 0;
globalThis.setTimeout = (f, ms, ...a) => { ttl = Math.max(ttl, ms || 0); return realSetTimeout(f, ms, ...a); };
await rules.allowNavigationOnce(7, re);
globalThis.setTimeout = realSetTimeout;
await rules.allowNavigationOnce(8, re);
console.log("rule ttl", ttl);
const tabsOf = () => sessionRules.map((r) => r.condition.tabIds[0]).join(",") || "none";
const fire = async (event, tabId, url) => { for (const f of chrome.webRequest[event].fs) f({ tabId, url }); await settle(); };
await fire("onCompleted", 7, "https://shop.example.com/other");
console.log("rules other-address", tabsOf());
await fire("onCompleted", 7, "https://shop.example.com/pay?order=1");
console.log("rules completed", tabsOf());
await fire("onErrorOccurred", 8, "https://shop.example.com/pay");
console.log("rules errored", tabsOf());
process.exit(0);
`
