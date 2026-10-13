// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// `pclaw hook claude-code` is the Claude Code PreToolUse hook (G0 M6
// design decision 16; HR-186, HR-187): the PantherClaw plugin runs it for
// every command a tool runs in a shell: Bash, PowerShell and Monitor, whose
// command runs where Bash's does and is decided as a bash command (HR-186,
// widened after review, founder decision 2026-10-13). It reads the hook
// input, resolves the working directory to its final form, signs a PAP/1
// request with the developer's desktop workload key (L1, HR-092) in the
// configured run, and asks the gateway's /hook/{connection}.
//
// It answers allow only when PantherClaw allowed and recorded the command.
// Everything else blocks it (exit code 2, the reason on stderr): a denial,
// a hold, which it never turns into a question for the local user, and any
// error or answer that does not arrive within its own deadline, which is
// shorter than the hook's timeout because Claude Code runs the tool when a
// hook times out (fail closed, decision 4).

func init() {
	commands["hook claude-code"] = command{
		usage: "hook claude-code [--gateway URL] [--connection NAME] [--key-file FILE] [--run ID] [--token-file FILE]",
		run:   hookClaudeCode,
	}
}

// hookDeadline bounds a hook decision, below the plugin's 10-second hook
// timeout; a variable for tests.
var hookDeadline = 8 * time.Second

// Bounds and patterns of the hook input.
const hookMaxInput = 1 << 20

var hookCallPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// shellOf is the shell that runs each tool's command (tool_input.command),
// as the gateway's pc.shell mapping names it. Monitor runs its command
// where Bash runs, so it is decided exactly as a bash command; a Monitor
// call without one is not decided, and so is blocked.
var shellOf = map[string]string{"Bash": "bash", "PowerShell": "powershell", "Monitor": "bash"}

// hookInput is what the hook reads of Claude Code's PreToolUse input.
type hookInput struct {
	Event     string `json:"hook_event_name"`
	Tool      string `json:"tool_name"`
	ToolUseID string `json:"tool_use_id"`
	Cwd       string `json:"cwd"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

// hookAnswer is the gateway's answer (internal/gateway/hook.Answer).
type hookAnswer struct {
	Decision      string `json:"decision"`
	Reason        string `json:"reason"`
	TransactionID string `json:"transaction_id"`
}

func hookClaudeCode(ctx context.Context, a *app, args []string) error {
	ctx, cancel := context.WithTimeout(ctx, hookDeadline)
	defer cancel()
	ans, err := a.hookAsk(ctx, args)
	switch {
	case err != nil:
		return &exitError{code: 2, msg: "PantherClaw could not decide this command, so it is blocked: " + describe(err)}
	case ans.Decision != "allow":
		reason := ans.Reason
		if reason == "" {
			reason = "PantherClaw denied this command."
		}
		return &exitError{code: 2, msg: reason}
	}
	out := map[string]any{"hookSpecificOutput": map[string]string{
		"hookEventName": "PreToolUse", "permissionDecision": "allow", "permissionDecisionReason": ans.Reason,
	}}
	return json.MarshalWrite(a.stdout, out, json.Deterministic(true))
}

// hookAsk reads the hook input and asks the gateway.
func (a *app) hookAsk(ctx context.Context, args []string) (hookAnswer, error) {
	fs := flag.NewFlagSet("hook claude-code", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	env := func(name string) string { v, _ := a.env(name); return v }
	gateway := fs.String("gateway", env("PANTHERCLAW_GATEWAY"), "the gateway's public URL (PANTHERCLAW_GATEWAY)")
	conn := fs.String("connection", env("PANTHERCLAW_HOOK_CONNECTION"), "the kind-local connection (PANTHERCLAW_HOOK_CONNECTION)")
	keyFile := fs.String("key-file", env("PANTHERCLAW_WORKLOAD_KEY_FILE"), "the enrolled desktop workload key file (PANTHERCLAW_WORKLOAD_KEY_FILE)")
	runFlag := fs.String("run", env("PANTHERCLAW_RUN"), "the run (PANTHERCLAW_RUN; default: the key file's)")
	tokenFile := fs.String("token-file", "", "a workload token to use instead of issuing one")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return hookAnswer{}, errors.New("usage: pclaw " + commands["hook claude-code"].usage)
	}
	if *gateway == "" || *conn == "" || *keyFile == "" {
		return hookAnswer{}, errors.New("set --gateway, --connection and --key-file (or PANTHERCLAW_GATEWAY, PANTHERCLAW_HOOK_CONNECTION and PANTHERCLAW_WORKLOAD_KEY_FILE)")
	}
	raw, err := io.ReadAll(io.LimitReader(a.stdin, hookMaxInput+1))
	if err != nil || len(raw) > hookMaxInput {
		return hookAnswer{}, errors.New("the hook input cannot be read")
	}
	var in hookInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return hookAnswer{}, errors.New("the hook input is not Claude Code's PreToolUse JSON")
	}
	shell := shellOf[in.Tool]
	switch {
	case in.Event != "PreToolUse":
		return hookAnswer{}, fmt.Errorf("a %q hook event (only PreToolUse is decided)", in.Event)
	case shell == "":
		return hookAnswer{}, fmt.Errorf("the %q tool (only the commands Bash, PowerShell and Monitor run are decided)", in.Tool)
	case in.ToolInput.Command == "" && in.Tool == "Monitor":
		return hookAnswer{}, errors.New("a Monitor call without a command (its WebSocket form, say) is nothing PantherClaw decides")
	case in.ToolInput.Command == "":
		return hookAnswer{}, errors.New("the command is empty")
	}
	cwd, err := finalPath(in.Cwd)
	if err != nil {
		return hookAnswer{}, err
	}
	call := in.ToolUseID
	if !hookCallPattern.MatchString(call) {
		var b [16]byte
		_, _ = rand.Read(b[:])
		call = "pc-" + hex.EncodeToString(b[:])
	}
	base, err := checkServer(*gateway)
	if err != nil {
		return hookAnswer{}, errors.New("--gateway must be a base URL using https (http only for localhost)")
	}
	kf, err := workloadclient.ReadKeyFile(*keyFile)
	if err != nil {
		return hookAnswer{}, err
	}
	key, err := kf.Key()
	if err != nil {
		return hookAnswer{}, err
	}
	run := *runFlag
	if run == "" {
		run = kf.RunID
	}
	if _, err := ids.ParseUUID(run); err != nil {
		return hookAnswer{}, errors.New("no run: set --run or PANTHERCLAW_RUN (pclaw run start)")
	}
	token, err := a.hookToken(ctx, kf, *keyFile, *tokenFile)
	if err != nil {
		return hookAnswer{}, err
	}
	body, err := json.Marshal(map[string]any{"tool": "shell", "input": map[string]string{
		"shell": shell, "command": in.ToolInput.Command, "cwd": cwd, "call": call,
	}}, json.Deterministic(true))
	if err != nil {
		return hookAnswer{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/hook/"+url.PathEscape(*conn), bytes.NewReader(body))
	if err != nil {
		return hookAnswer{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("PAP-Run-Id", run)
	rt := a.http.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	client := &http.Client{
		Transport:     &workloadclient.Transport{Key: key, Base: rt, Token: func() string { return token }},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	res, err := client.Do(req)
	if err != nil {
		return hookAnswer{}, fmt.Errorf("the gateway did not answer: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	var ans hookAnswer
	if err := json.UnmarshalRead(io.LimitReader(res.Body, 64<<10), &ans); err != nil || (ans.Decision != "allow" && ans.Decision != "deny") {
		return hookAnswer{}, fmt.Errorf("the gateway answered HTTP %d without a decision", res.StatusCode)
	}
	if res.StatusCode != http.StatusOK {
		ans.Decision = "deny"
	}
	return ans, nil
}

// finalPath resolves a working directory to its absolute, final form where
// the file system can (links, junctions and short names, HR-187); the
// gateway then normalizes it lexically and refuses ambiguous forms.
func finalPath(p string) (string, error) {
	if p == "" {
		return "", errors.New("the hook input names no working directory")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if final, err := filepath.EvalSymlinks(abs); err == nil {
		return final, nil
	}
	return abs, nil
}

// hookToken returns a workload token: the one in tokenFile, or a cached one
// with more than a minute left, or a new one, which is cached next to the
// key file (0600) because every command is a new process.
func (a *app) hookToken(ctx context.Context, kf workloadclient.KeyFile, keyFile, tokenFile string) (string, error) {
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile) //nolint:gosec // G304: operator-chosen path
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	cache := keyFile + ".token"
	if b, err := os.ReadFile(cache); err == nil { //nolint:gosec // G304: next to the operator-chosen key file
		if tok := strings.TrimSpace(string(b)); time.Until(tokenExpiry(tok)) > time.Minute {
			return tok, nil
		}
	}
	if kf.Server == "" || kf.Identifier == "" {
		return "", errors.New("the key file is not enrolled yet: run pclaw workload enroll")
	}
	wc, err := a.workloadClient(kf.Server, kf)
	if err != nil {
		return "", err
	}
	res, err := wc.IssueToken(ctx, &pantherclawv1.IssueTokenRequest{Identifier: kf.Identifier})
	if err != nil {
		return "", fmt.Errorf("workload token: %w", err)
	}
	tok := res.GetWorkloadToken()
	_ = os.WriteFile(cache, []byte(tok+"\n"), 0o600) // a cache: a failed write only costs the next command a token
	return tok, nil
}

// tokenExpiry reads, without verifying, a workload token's expiry (its
// exp claim), or the zero time.
func tokenExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var c struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &c) != nil || c.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(c.Exp, 0)
}
