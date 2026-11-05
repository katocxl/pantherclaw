// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	binenc "encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// `pclaw browser host` is the Chrome native messaging host of the managed
// PantherClaw extension (G0 M33 D979, HR-753). Chrome starts it for the
// extension, and the extension reaches PantherClaw only through it (FQ33-1):
// no key lives in the browser, and the gateway's hook face still refuses
// any request with an Origin. Each decide message becomes one PAP/1 hook
// call, signed with the desktop workload key in the configured run. Any
// error is a deny with code CANNOT_DECIDE (fail closed). It never logs a
// message's input, and it exits when Chrome closes its stdin.

func init() {
	commands["browser host"] = command{
		usage: "browser host --config FILE [chrome-extension://ID/] [--parent-window=N]",
		run:   browserHost,
	}
}

// Bounds of the native messaging channel (D979).
const (
	browserHostMaxIn    = 1 << 20  // an inbound message; a larger one closes the host
	browserHostMaxOut   = 64 << 10 // a reply
	browserHostMaxInput = 64 << 10 // a decide message's input
	browserHostName     = "dev.pantherclaw.browser"
	browserCannotDecide = "CANNOT_DECIDE"
)

// browserHostDeadline bounds one decide call, like hookDeadline; a variable
// for tests.
var browserHostDeadline = 8 * time.Second

// browserTools are the hook tools a decide message may name: the pc.browser
// tools (D974) and the pc.computer tool (D984).
var browserTools = []string{
	"browser_navigate", "browser_submit", "browser_download", "browser_click", "browser_takeover", "computer",
}

// extensionIDPattern is a Chrome extension id.
var extensionIDPattern = regexp.MustCompile(`^[a-p]{32}$`)

// browserHostConfig is the host's configuration file (written by
// `pclaw browser install-host`).
type browserHostConfig struct {
	Gateway      string   `json:"gateway"`
	Connection   string   `json:"connection"`
	KeyFile      string   `json:"key_file"`
	Run          string   `json:"run"`
	ExtensionIDs []string `json:"extension_ids"`
}

// browserHostIn is one message from the extension.
type browserHostIn struct {
	V        int            `json:"v"`
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Tool     string         `json:"tool"`
	ActionID string         `json:"action_id"`
	Input    jsontext.Value `json:"input"`
}

// browserDecideOut answers a decide message.
type browserDecideOut struct {
	V             int    `json:"v"`
	ID            string `json:"id"`
	Decision      string `json:"decision"`
	Held          bool   `json:"held"`
	Code          string `json:"code"`
	Reason        string `json:"reason"`
	TransactionID string `json:"transaction_id"`
}

// browserStatusOut answers a status message.
type browserStatusOut struct {
	V          int    `json:"v"`
	ID         string `json:"id"`
	OK         bool   `json:"ok"`
	Connection string `json:"connection"`
	Run        string `json:"run"`
	Reason     string `json:"reason"`
}

// readBrowserHostConfig reads and checks the configuration file. On unix a
// file group or others can read is refused: it names the key file.
func readBrowserHostConfig(path string) (browserHostConfig, error) {
	var cfg browserHostConfig
	fi, err := os.Stat(path)
	if err != nil {
		return cfg, fmt.Errorf("the host configuration: %w", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return cfg, fmt.Errorf("the host configuration %s is readable by group or others: chmod 600 it", path)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: operator-chosen path
	if err != nil {
		return cfg, fmt.Errorf("the host configuration: %w", err)
	}
	if err := json.Unmarshal(raw, &cfg, json.RejectUnknownMembers(true)); err != nil {
		return cfg, fmt.Errorf("the host configuration is not valid JSON: %w", err)
	}
	if cfg.Gateway == "" || cfg.Connection == "" || cfg.KeyFile == "" || len(cfg.ExtensionIDs) == 0 {
		return cfg, errors.New("the host configuration needs gateway, connection, key_file and extension_ids")
	}
	for _, id := range cfg.ExtensionIDs {
		if !extensionIDPattern.MatchString(id) {
			return cfg, fmt.Errorf("the host configuration names an extension id that is not one: %q", id)
		}
	}
	return cfg, nil
}

// browserHostArgs parses the host's arguments. Chrome appends the caller's
// origin and, on Windows, --parent-window=N after the wrapper's own
// arguments, so they are read by hand.
func browserHostArgs(args []string) (config, origin string, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--config" || arg == "-config":
			if i+1 >= len(args) {
				return "", "", errUsage
			}
			i++
			config = args[i]
		case strings.HasPrefix(arg, "--config="):
			config = strings.TrimPrefix(arg, "--config=")
		case strings.HasPrefix(arg, "--parent-window="):
		case strings.HasPrefix(arg, "chrome-extension://") && origin == "":
			origin = arg
		default:
			return "", "", errUsage
		}
	}
	if config == "" {
		return "", "", errUsage
	}
	return config, origin, nil
}

func browserHost(ctx context.Context, a *app, args []string) error {
	cfgPath, origin, err := browserHostArgs(args)
	if err != nil {
		return err
	}
	cfg, err := readBrowserHostConfig(cfgPath)
	if err != nil {
		return &exitError{code: 1, msg: "pclaw browser host: " + err.Error()}
	}
	id, ok := strings.CutPrefix(origin, "chrome-extension://")
	id, slash := strings.CutSuffix(id, "/")
	if !ok || !slash || !slices.Contains(cfg.ExtensionIDs, id) {
		// Nothing on stdout: Chrome reads only framed messages there.
		return &exitError{code: 1, msg: "pclaw browser host: the caller is not a configured extension"}
	}
	h := &browserHostState{a: a, cfg: cfg, out: a.stdout}
	return h.serve(ctx, a.stdin)
}

// browserHostState is one running host.
type browserHostState struct {
	a   *app
	cfg browserHostConfig

	outMu sync.Mutex
	out   io.Writer

	tokMu sync.Mutex
	token string
}

// serve reads framed messages until stdin ends (or a message is too large
// or not framed), answering each; decide calls run concurrently.
func (h *browserHostState) serve(ctx context.Context, in io.Reader) error {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	for {
		var n uint32
		if err := binenc.Read(in, binenc.LittleEndian, &n); err != nil {
			// EOF: Chrome closed the port; anything else ends the host too.
			return nil
		}
		if n > browserHostMaxIn {
			_, _ = fmt.Fprintln(h.a.stderr, "pclaw browser host: a message over 1 MiB; closing")
			return nil
		}
		raw := make([]byte, n)
		if _, err := io.ReadFull(in, raw); err != nil {
			return nil
		}
		var msg browserHostIn
		if err := json.Unmarshal(raw, &msg); err != nil || msg.V != 1 {
			_, _ = fmt.Fprintln(h.a.stderr, "pclaw browser host: a message that is not v1 JSON is ignored")
			continue
		}
		if _, err := ids.ParseUUID(msg.ID); err != nil {
			_, _ = fmt.Fprintln(h.a.stderr, "pclaw browser host: a message without a valid id is ignored")
			continue
		}
		switch msg.Type {
		case "decide":
			wg.Add(1)
			go func() { defer wg.Done(); h.reply(h.decide(ctx, msg)) }()
		case "status":
			wg.Add(1)
			go func() { defer wg.Done(); h.reply(h.status(ctx, msg)) }()
		default:
			_, _ = fmt.Fprintln(h.a.stderr, "pclaw browser host: a message of an unknown type is ignored")
		}
	}
}

// decide asks the gateway about one browser action.
func (h *browserHostState) decide(ctx context.Context, msg browserHostIn) browserDecideOut {
	out := browserDecideOut{V: 1, ID: msg.ID, Decision: "deny", Code: browserCannotDecide}
	fail := func(why string) browserDecideOut {
		out.Reason = "PantherClaw cannot decide this call, so it does not happen: " + why
		return out
	}
	switch {
	case !slices.Contains(browserTools, msg.Tool):
		return fail("the tool is not a browser tool PantherClaw decides")
	case len(msg.Input) > browserHostMaxInput || msg.Input.Kind() != '{':
		return fail("the input must be a JSON object of at most 64 KiB")
	case msg.ActionID != "":
		if _, err := ids.ParseUUID(msg.ActionID); err != nil {
			return fail("the action id is not a UUID")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, browserHostDeadline)
	defer cancel()
	ans, err := h.a.hookPost(ctx, h.target(), msg.Tool, msg.Input, msg.ActionID)
	if err != nil {
		return fail(describe(err))
	}
	out.Decision, out.Held, out.Code, out.Reason, out.TransactionID = ans.Decision, ans.Held, ans.Code, ans.Reason, ans.TransactionID
	if out.Decision != "allow" {
		out.Decision = "deny"
	}
	return out
}

// status says whether the host can sign calls: the key file reads, the run
// is set and a workload token is at hand.
func (h *browserHostState) status(ctx context.Context, msg browserHostIn) browserStatusOut {
	out := browserStatusOut{V: 1, ID: msg.ID, Connection: h.cfg.Connection}
	ctx, cancel := context.WithTimeout(ctx, browserHostDeadline)
	defer cancel()
	kf, err := workloadclient.ReadKeyFile(h.cfg.KeyFile)
	if err != nil {
		out.Reason = "the workload key file cannot be read"
		return out
	}
	out.Run = h.cfg.Run
	if out.Run == "" {
		out.Run = kf.RunID
	}
	if _, err := ids.ParseUUID(out.Run); err != nil {
		out.Reason = "no run is configured"
		return out
	}
	if _, err := h.workloadToken(ctx, kf); err != nil {
		out.Reason = "no workload token: " + describe(err)
		return out
	}
	out.OK = true
	return out
}

func (h *browserHostState) target() hookTarget {
	return hookTarget{gateway: h.cfg.Gateway, conn: h.cfg.Connection, keyFile: h.cfg.KeyFile, run: h.cfg.Run, token: h.workloadToken}
}

// workloadToken returns the token kept in memory, renewed when less than a
// minute is left.
func (h *browserHostState) workloadToken(ctx context.Context, kf workloadclient.KeyFile) (string, error) {
	h.tokMu.Lock()
	defer h.tokMu.Unlock()
	if h.token != "" && time.Until(tokenExpiry(h.token)) > time.Minute {
		return h.token, nil
	}
	tok, err := h.a.issueHookToken(ctx, kf)
	if err != nil {
		return "", err
	}
	h.token = tok
	return tok, nil
}

// reply writes one framed reply. A reply over 64 KiB is replaced by a
// deny (or a failed status) without its reason.
func (h *browserHostState) reply(v any) {
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil || len(b) > browserHostMaxOut {
		switch r := v.(type) {
		case browserDecideOut:
			b, _ = json.Marshal(browserDecideOut{V: 1, ID: r.ID, Decision: "deny", Code: browserCannotDecide})
		case browserStatusOut:
			b, _ = json.Marshal(browserStatusOut{V: 1, ID: r.ID, Connection: r.Connection})
		default:
			return
		}
	}
	var n [4]byte
	binenc.LittleEndian.PutUint32(n[:], uint32(len(b))) //nolint:gosec // G115: at most 64 KiB
	h.outMu.Lock()
	defer h.outMu.Unlock()
	_, _ = h.out.Write(append(n[:], b...))
}
