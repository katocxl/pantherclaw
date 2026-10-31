// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/recommendations/domain"
)

// scanServer records what a scan submits, as the bytes that leave the machine.
func scanServer(t *testing.T) (*recordScan, *string, func(string) (string, bool)) {
	t.Helper()
	rec := &recordScan{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterAgentServiceHandler(cs, rec)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	env := map[string]string{"PANTHERCLAW_SERVER": srv.URL, "PANTHERCLAW_API_KEY": "pck_test", "PANTHERCLAW_CONFIG_DIR": t.TempDir()}
	return rec, &auth, func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestHR588_ScanSendsMetadataOnly: every place a scan reads holds a canary:
// hook arguments and environment prefixes, prompt and URL hooks, matchers,
// skill bodies, server arguments, docker secrets, file contents next to a
// config. The submitted request carries none of them, and each closed kind
// carries exactly its named attributes.
// Covers: T-255
func TestHR588_ScanSendsMetadataOnly(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		".claude/settings.json": `{"hooks": {
			"PreToolUse": [{"matcher": "CANARY-MATCHER", "hooks": [
				{"type": "command", "command": "TOKEN=CANARY-ENV /opt/hooks/guard.sh --key CANARY-ARG"},
				{"type": "prompt", "prompt": "CANARY-PROMPT"},
				{"type": "http", "url": "https://hooks.example/CANARY-URL"}]}],
			"Stop": [{"hooks": [{"type": "command", "command": "bash -c 'curl https://x/CANARY-SHELL'"}]}],
			"CANARY EVENT with text": [{"hooks": [{"type": "command", "command": "evil"}]}]}}`,
		".claude/skills/review/SKILL.md":   "---\nname: review\n---\nCANARY-SKILL-BODY\n",
		".claude/skills/review/helper.py":  "CANARY-SKILL-FILE",
		".claude/skills/not-a-skill/x.txt": "CANARY-NOT-SKILL",
		".cursor/hooks.json":               `{"version": 1, "hooks": {"beforeShellExecution": [{"command": "./audit.sh CANARY-CURSOR"}]}}`,
		"CLAUDE.md":                        "CANARY-PROJECT-FILE",
		"prompt.txt":                       "CANARY-PROMPT-FILE",
		".mcp.json": `{"mcpServers": {
			"gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github", "--token", "CANARY-NPX"]},
			"git": {"command": "uvx", "args": ["--from", "mcp-server-git", "mcp-server-git", "--repository", "/CANARY-UVX"]},
			"box": {"command": "docker", "args": ["run", "-i", "--rm", "-e", "TOKEN=CANARY-DOCKER", "ghcr.io/acme/mcp:1.2", "--secret", "CANARY-IMAGE-ARG"]},
			"odd": {"command": "docker", "args": ["run", "--unknown-flag", "CANARY-UNKNOWN", "ghcr.io/acme/mcp:1"]},
			"url": {"command": "npx", "args": ["https://user:CANARY-URLARG@host/x"]},
			"local": {"command": "python", "args": ["server.py", "CANARY-PYTHON"]},
			"key": {"command": "node", "env": {"ANTHROPIC_API_KEY": "sk-ant-CANARY-VALUE", "OTHER_TOKEN": "pck_CANARY-PCK"}}}}`,
	})
	rec, _, env := scanServer(t)
	if code, out, errs := run(t, env, "scan", "--path", dir, "--no-user-config", "--no-env", "--submit"); code != 0 {
		t.Fatalf("scan = %d %q %q", code, out, errs)
	}
	if rec.req == nil {
		t.Fatal("nothing was submitted")
	}
	if s := rec.req.String(); strings.Contains(s, "CANARY") {
		t.Fatalf("a canary left the machine: %s", regexp.MustCompile(`CANARY[-A-Z ]*`).FindAllString(s, -1))
	}
	refs, kinds := map[string]string{}, map[string]int{}
	for _, f := range rec.req.GetFindings() {
		kinds[f.GetKind()]++
		at := f.GetAttributes()
		switch f.GetKind() {
		case "hook":
			for k := range at {
				if k != "event" && k != "executable" {
					t.Errorf("hook attribute %q", k)
				}
			}
		case "skill":
			if len(at) != 2 || at["name"] != "review" || !strings.HasSuffix(filepath.ToSlash(at["path"]), ".claude/skills/review") {
				t.Errorf("skill %v", at)
			}
		case "env_secret":
			if len(at) != 1 || at["secret_kind"] != "anthropic_api_key" {
				t.Errorf("env_secret %v", at)
			}
		case "mcp_server":
			refs[at["name"]] = at["package_ref"]
		}
	}
	if kinds["hook"] != 4 || kinds["skill"] != 1 || kinds["env_secret"] != 1 {
		t.Errorf("kinds = %v", kinds)
	}
	want := map[string]string{
		"gh": "@modelcontextprotocol/server-github", "git": "mcp-server-git", "box": "ghcr.io/acme/mcp:1.2",
		"odd": "", "url": "", "local": "", "key": "",
	}
	for name, ref := range want {
		if refs[name] != ref {
			t.Errorf("package_ref of %s = %q, want %q", name, refs[name], ref)
		}
	}
}

// TestHR588_OtherCredentialKindsStayOnTheMachine: only the kinds the
// recommendations read are reported as present, and the list is the
// catalogue's, so a new catalogue kind cannot silently stay dark (D238).
// Covers: F343
func TestHR588_OtherCredentialKindsStayOnTheMachine(t *testing.T) {
	want := domain.SecretKinds()
	slices.Sort(want)
	got := slices.Clone(scanSecretKindsForTest())
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("scan kinds %v, catalogue kinds %v", got, want)
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{".mcp.json": `{"mcpServers": {"s": {"command": "node",
		"env": {"GITHUB_TOKEN": "ghp_0123456789", "PANTHERCLAW_API_KEY": "pck_0123456789", "AWS_SECRET_ACCESS_KEY": "abcdefgh12345678"}}}}`})
	rec, _, env := scanServer(t)
	if code, out, errs := run(t, env, "scan", "--path", dir, "--no-user-config", "--no-env", "--submit"); code != 0 {
		t.Fatalf("scan = %d %q %q", code, out, errs)
	}
	var sent []string
	for _, f := range rec.req.GetFindings() {
		if f.GetKind() == "env_secret" {
			sent = append(sent, f.GetAttributes()["secret_kind"])
		}
	}
	if !slices.Equal(sent, []string{"aws_secret_access_key"}) {
		t.Fatalf("credential kinds sent: %v", sent)
	}
}

// TestF343_ScanSubmitsTheSignalRecommendationsRead: the discovery a
// submission makes has the shape RecommendationOpenSecrets matches: kind
// env_secret with a closed secret_kind (D238).
// Covers: F343
func TestF343_ScanSubmitsTheSignalRecommendationsRead(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{".mcp.json": `{"mcpServers": {"s": {"command": "node", "env": {"OPENAI_API_KEY": "sk-proj-0123456789"}}}}`})
	rec, _, env := scanServer(t)
	if code, out, errs := run(t, env, "scan", "--path", dir, "--no-user-config", "--no-env", "--submit"); code != 0 {
		t.Fatalf("scan = %d %q %q", code, out, errs)
	}
	if !slices.ContainsFunc(rec.req.GetFindings(), func(f *pantherclawv1.ScanFinding) bool {
		return f.GetKind() == "env_secret" && f.GetAttributes()["secret_kind"] == "openai_api_key"
	}) {
		t.Fatalf("no signal in %v", rec.req)
	}
}

// TestScanDeviceScope (D234): the scope is device: and 16 hex digits, stable
// across runs, different with another salt, and it does not hold the machine
// id; --device goes with --submit and without --scope or --complete.
func TestScanDeviceScope(t *testing.T) {
	old := machineID
	t.Cleanup(func() { machineID = old })
	machineID = func() (string, error) { return "machine-1234", nil }
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{".mcp.json": `{"mcpServers": {"s": {"command": "python"}}}`})
	rec, _, env := scanServer(t)
	for range 2 {
		if code, out, errs := run(t, env, "scan", "--path", dir, "--no-user-config", "--no-env", "--submit", "--device"); code != 0 {
			t.Fatalf("scan = %d %q %q", code, out, errs)
		}
	}
	first := rec.req.GetScope()
	if !regexp.MustCompile(`^device:[0-9a-f]{16}$`).MatchString(first) {
		t.Fatalf("scope %q", first)
	}
	again, err := deviceScope(env)
	if err != nil || again != first {
		t.Fatalf("second read = %q, %v; want %q", again, err, first)
	}
	other, err := deviceScope(func(k string) (string, bool) {
		if k == "PANTHERCLAW_CONFIG_DIR" {
			return t.TempDir(), true
		}
		return "", false
	})
	if err != nil || other == first {
		t.Fatalf("another salt = %q, %v", other, err)
	}
	for _, args := range [][]string{{"scan", "--device"}, {"scan", "--submit", "--device", "--scope", "x"}, {"scan", "--submit", "--device", "--complete"}} {
		if code, out, errs := run(t, env, args...); code == 0 {
			t.Errorf("%v = %d %q %q", args, code, out, errs)
		}
	}
}

// TestScanAllUsers (D235): --all-users needs root or SYSTEM; it reads each
// home with the same metadata, and a link in a home reaches nothing outside.
func TestScanAllUsers(t *testing.T) {
	old := privileged
	t.Cleanup(func() { privileged = old })
	privileged = func() bool { return false }
	_, _, env := scanServer(t)
	if code, _, errs := run(t, env, "scan", "--all-users"); code == 0 || !strings.Contains(errs, "root or SYSTEM") {
		t.Fatalf("unprivileged --all-users = %d %q", code, errs)
	}
	root := t.TempDir()
	outside := t.TempDir()
	writeTree(t, outside, map[string]string{"private.json": `{"mcpServers": {"outside": {"command": "secret-tool"}}}`})
	writeTree(t, root, map[string]string{
		"ann/.cursor/mcp.json":      `{"mcpServers": {"tickets": {"command": "python", "args": ["CANARY-ARG"]}}}`,
		"bob/.claude/settings.json": `{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "guard.sh CANARY-HOOK"}]}]}}`,
		"Public/.cursor/mcp.json":   `{"mcpServers": {"public": {"command": "python"}}}`,
	})
	mallory := filepath.Join(root, "mal", ".cursor")
	if err := os.MkdirAll(mallory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "private.json"), filepath.Join(mallory, "mcp.json")); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	homes := userHomes([]string{root})
	if len(homes) != 3 {
		t.Fatalf("homes = %v", homes)
	}
	var names []string
	for _, f := range scanAllUsers("host", nil, homes) {
		names = append(names, f.Kind+":"+f.Attributes["name"]+f.Attributes["executable"])
		if strings.Contains(strings.Join(mapValues(f.Attributes), " "), "CANARY") {
			t.Errorf("a canary in %v", f)
		}
	}
	slices.Sort(names)
	if want := []string{"hook:guard.sh", "mcp_server:tickets"}; !slices.Equal(names, want) {
		t.Fatalf("findings %v, want %v", names, want)
	}
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// TestScanAPIKeyFile (D235): the key comes from PANTHERCLAW_API_KEY_FILE when
// PANTHERCLAW_API_KEY is unset; a file holding more than one word is refused.
func TestScanAPIKeyFile(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{".mcp.json": `{"mcpServers": {"s": {"command": "python"}}}`, "key": "pck_fromfile\n", "bad": "pck_a\npck_b\n"})
	_, auth, base := scanServer(t)
	for _, c := range []struct {
		file string
		ok   bool
	}{{filepath.Join(dir, "key"), true}, {filepath.Join(dir, "bad"), false}, {filepath.Join(dir, "none"), false}} {
		env := func(k string) (string, bool) {
			switch k {
			case "PANTHERCLAW_API_KEY":
				return "", false
			case "PANTHERCLAW_API_KEY_FILE":
				return c.file, true
			}
			return base(k)
		}
		code, out, errs := run(t, env, "scan", "--path", dir, "--no-user-config", "--no-env", "--submit")
		if (code == 0) != c.ok {
			t.Fatalf("%s = %d %q %q", c.file, code, out, errs)
		}
		if c.ok && *auth != "Bearer pck_fromfile" {
			t.Fatalf("auth = %q", *auth)
		}
	}
}

// TestScanSchedule (D237): each scheduler gets the scan with --every, never a
// key in its definition; an all-users schedule is the machine's own.
func TestScanSchedule(t *testing.T) {
	env := map[string]string{"PANTHERCLAW_SERVER": "https://pc.example", "PANTHERCLAW_API_KEY_FILE": "/etc/pantherclaw/key"}
	base := scanSchedule{exe: "/opt/pclaw", home: "/home/ann", every: 24 * time.Hour, env: env}
	for _, c := range []struct {
		goos     string
		allUsers bool
		want     []string
	}{
		{"linux", false, []string{"systemctl --user enable --now pantherclaw-scan.timer", "OnUnitActiveSec=86400s", "scan --submit --device --no-env"}},
		{"linux", true, []string{"systemctl enable --now pantherclaw-scan.timer", "/etc/systemd/system/pantherclaw-scan.timer", "--all-users"}},
		{"darwin", false, []string{"launchctl bootstrap gui/", "<integer>86400</integer>", "<string>--device</string>"}},
		{"darwin", true, []string{"launchctl bootstrap system", "/Library/LaunchDaemons/dev.pantherclaw.scan.plist", "<string>--all-users</string>"}},
		{"windows", false, []string{"/SC DAILY /MO 1", `"/opt/pclaw" scan --submit --device --no-env`}},
		{"windows", true, []string{"/RU SYSTEM", "--all-users"}},
	} {
		s := base
		s.goos, s.allUsers = c.goos, c.allUsers
		spec, err := s.spec()
		if err != nil {
			t.Fatalf("%s: %v", c.goos, err)
		}
		var b strings.Builder
		for path, content := range spec.files {
			b.WriteString(path + "\n" + content + "\n")
		}
		for _, cmd := range spec.install {
			b.WriteString(strings.Join(cmd, " ") + "\n")
		}
		text := b.String()
		for _, w := range c.want {
			if !strings.Contains(text, w) {
				t.Errorf("%s all=%v: no %q in\n%s", c.goos, c.allUsers, w, text)
			}
		}
		if strings.Contains(text, "PANTHERCLAW_API_KEY=") || strings.Contains(text, "<key>PANTHERCLAW_API_KEY</key>") {
			t.Errorf("%s: a key in the definition:\n%s", c.goos, text)
		}
	}
	for _, d := range []time.Duration{time.Minute, 1000 * time.Hour, 90 * time.Second} {
		if checkEvery(d) == nil {
			t.Errorf("--every %v accepted", d)
		}
	}
	w := scanSchedule{goos: "windows", exe: "x", every: 36 * time.Hour}
	if _, err := w.spec(); err == nil {
		t.Error("Windows accepted 36h")
	}
	if _, err := (scanSchedule{goos: "plan9"}).spec(); err == nil {
		t.Error("an unknown platform was accepted")
	}
}
