// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// initPlan is everything `pclaw init` would change. All of it is shown,
// and none of it is done until the person confirms (HR-208).
type initPlan struct {
	enroll *enrollment
	// edits are the files init adds to, their documents changed in place.
	edits []*claudeSettings
	// done is printed once the changes are made.
	done []string
}

// file is the plan's copy of a file, so two additions to one file land in
// one document.
func (p *initPlan) file(s claudeSettings) *claudeSettings {
	for _, e := range p.edits {
		if samePath(e.path, s.path) {
			return e
		}
	}
	p.edits = append(p.edits, &s)
	return &s
}

// addHook adds the hook to the target file's PreToolUse hooks.
func (p *initPlan) addHook(target claudeSettings, hook *jsonNode) error {
	s := p.file(target)
	hooks, ok := s.doc.object("hooks")
	if !ok {
		return &exitError{code: 1, msg: "pclaw init: " + s.path + ": hooks is not an object; it is left as it is"}
	}
	pre, ok := hooks.array("PreToolUse")
	if !ok {
		return &exitError{code: 1, msg: "pclaw init: " + s.path + ": hooks.PreToolUse is not a list; it is left as it is"}
	}
	pre.items = append(pre.items, hook)
	p.done = append(p.done, "Every Bash, PowerShell and Monitor command now asks PantherClaw first; when it cannot answer, the command is blocked.")
	return nil
}

func samePath(a, b string) bool {
	a, b = filepath.ToSlash(filepath.Clean(a)), filepath.ToSlash(filepath.Clean(b))
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// initWrite is one file init replaces: the bytes the plan was made from
// (nil for a file that did not exist) and the new content.
type initWrite struct {
	path          string
	before, after []byte
}

// unchanged fails when a file is no longer what the plan was made from.
// Claude Code rewrites its settings and ~/.claude.json while it runs, and
// the person may take a while to answer, so writing the plan then would
// lose what changed meanwhile (a deny rule added, say). done says what
// init has done by then.
func unchanged(writes []initWrite, done string) error {
	for _, w := range writes {
		now, err := os.ReadFile(w.path)
		if errors.Is(err, os.ErrNotExist) {
			now = nil
		} else if err != nil {
			return err
		}
		if (now == nil) != (w.before == nil) || !bytes.Equal(now, w.before) {
			return &exitError{code: 1, msg: "pclaw init: " + w.path + " changed after init read it (Claude Code rewrites its settings " +
				"while it runs); " + done + ", so run pclaw init again"}
		}
	}
	return nil
}

// apply shows the plan, asks, and carries it out: the enrollment first, so
// a hook never names a key that is not enrolled, then each file, unless it
// changed since the plan was made, backed up and replaced through a
// temporary file.
func (f initFlags) apply(ctx context.Context, a *app, p *initPlan) error {
	var writes []initWrite
	for _, s := range p.edits {
		after, err := s.doc.encode()
		if err != nil {
			return err
		}
		if after = likeOriginal(s.raw, after); bytes.Equal(after, s.raw) {
			continue
		}
		if _, err := fmt.Fprint(a.stdout, lineDiff(s.path, s.raw, after)); err != nil {
			return err
		}
		writes = append(writes, initWrite{s.path, s.raw, after})
	}
	if e := p.enroll; e != nil {
		key := "the workload key in " + e.path
		if e.create {
			key = "a new workload key in " + e.path + " (mode 0600)"
		}
		_, _ = fmt.Fprintf(a.stdout, "Enroll %s as agent %s, signed in as you, and admit it with the key's fingerprint\n  %s\n",
			key, e.agent, e.fingerprint)
	}
	switch {
	case p.enroll == nil && len(writes) == 0:
		_, err := fmt.Fprintln(a.stdout, "Nothing to change.")
		return err
	case f.dryRun:
		_, err := fmt.Fprintln(a.stdout, "Dry run: nothing was changed.")
		return err
	case !f.yes && !confirm(a, "Make these changes?"):
		return &exitError{code: 1, msg: "pclaw init: not confirmed; nothing was changed"}
	}
	done := "nothing was changed"
	if p.enroll != nil {
		// A file that changed while the person read the plan stops
		// everything, the enrollment (which writes the key file) too.
		if err := unchanged(writes, done); err != nil {
			return err
		}
		if err := p.enroll.run(ctx, a); err != nil {
			return err
		}
		// A file that changed during the enrollment's calls is still left
		// as it is, but the key is enrolled by then.
		done = "the key in " + p.enroll.path + " is enrolled and admitted, but no settings file was written"
	}
	if err := unchanged(writes, done); err != nil {
		return err
	}
	for _, w := range writes {
		backup, err := backupFile(w.path, time.Now())
		if err != nil {
			return err
		}
		if err := writeAtomically(w.path, w.after); err != nil {
			return err
		}
		if backup != "" {
			_, _ = fmt.Fprintf(a.stdout, "Backed up %s to %s.\n", w.path, backup)
		}
		_, _ = fmt.Fprintf(a.stdout, "Wrote %s.\n", w.path)
	}
	for _, d := range p.done {
		_, _ = fmt.Fprintln(a.stdout, d)
	}
	return nil
}

// confirm asks on stdout and reads one line from stdin: only y or yes
// agrees, and no answer (end of input) is no.
func confirm(a *app, question string) bool {
	_, _ = fmt.Fprintf(a.stdout, "%s [y/N] ", question)
	line, _ := bufio.NewReader(io.LimitReader(a.stdin, 64)).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	_, _ = fmt.Fprintln(a.stdout)
	return false
}

// enrollment is enrolling the key file as the signed-in person: the key,
// new or from the file, and the fingerprint shown before anything is done.
type enrollment struct {
	agent, path, fingerprint string
	kf                       workloadclient.KeyFile
	// create: the key file does not exist yet; the key is only in memory.
	create bool
}

// enrollment returns what enrolling the key file takes, or nil when it is
// enrolled already.
func (f initFlags) enrollment() (*enrollment, error) {
	path, err := filepath.Abs(f.keyFile)
	if err != nil {
		return nil, err
	}
	e := &enrollment{agent: f.agent, path: path}
	switch kf, err := workloadclient.ReadKeyFile(path); {
	case err == nil && kf.Identifier != "":
		return nil, nil
	case err == nil:
		// The file is rewritten in place with the identifier and keeps its
		// mode (on Windows, its owner and access list), so a key other
		// users can read (and may have read) is not enrolled.
		if who, fix, err := keyFileReaders(path); err != nil {
			return nil, fmt.Errorf("--key-file: %w", err)
		} else if who != "" {
			return nil, fmt.Errorf("--key-file %s holds a private key and other users can read or change it (%s), so init "+
				"does not enroll it: if no one else can have read it, %s; otherwise remove it, and init makes a new key", path, who, fix)
		}
		e.kf = kf
	case errors.Is(err, os.ErrNotExist):
		if e.kf, _, err = workloadclient.NewKeyFile(); err != nil {
			return nil, err
		}
		e.create = true
	default:
		return nil, fmt.Errorf("--key-file: %w", err)
	}
	if f.agent == "" {
		return nil, errors.New("--key-file is not an enrolled workload key: pass --agent AGENT_ID to enroll it as yourself (after pclaw login)")
	}
	if _, err := ids.ParseUUID(f.agent); err != nil {
		return nil, errors.New("--agent must be an agent id")
	}
	key, err := e.kf.Key()
	if err != nil {
		return nil, fmt.Errorf("--key-file: %w", err)
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	e.fingerprint = jws.Thumbprint(pub)
	// HR-094: a person confirms the key's fingerprint before it is
	// admitted. Without --yes they do so by confirming the plan, which
	// shows it; with --yes no one is asked, so they name it.
	switch {
	case f.yes && e.create:
		return nil, fmt.Errorf("--yes enrolls without asking, so it needs --fingerprint with the key's fingerprint, which you check (HR-094), "+
			"and a key init would create has none yet: create it first (pclaw workload init --key-file %s shows its fingerprint), "+
			"or run init without --yes", path)
	case f.yes && f.fingerprint == "":
		return nil, errors.New("--yes enrolls without asking, so it needs --fingerprint with the fingerprint of the key in --key-file, " +
			"which you check (HR-094; --dry-run shows it)")
	case f.fingerprint != "" && f.fingerprint != e.fingerprint:
		return nil, fmt.Errorf("--fingerprint %s is not the fingerprint of the key in %s; nothing was changed", f.fingerprint, path)
	}
	return e, nil
}

// run enrolls the key as the signed-in person: an enrollment token for the
// agent, used at once and kept nowhere; the workload's enrollment with it;
// and admission with the fingerprint shown before (HR-094), which the
// server checks against the enrolled key.
func (e *enrollment) run(ctx context.Context, a *app) error {
	s, err := a.session()
	if err != nil {
		return err
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	tok, err := c.identity.CreateEnrollmentToken(ctx, &pantherclawv1.CreateEnrollmentTokenRequest{AgentId: e.agent, TtlMinutes: 5})
	if err != nil {
		return fmt.Errorf("an enrollment token for agent %s: %w", e.agent, err)
	}
	if e.create {
		if err := workloadclient.WriteKeyFile(e.path, e.kf, false); err != nil {
			return err
		}
	}
	key, _ := e.kf.Key()
	pub, _ := key.Public().(ed25519.PublicKey)
	jwk, err := json.Marshal(jws.PublicJWK(pub, ""))
	if err != nil {
		return err
	}
	wc, err := a.workloadClient(s.server, e.kf)
	if err != nil {
		return err
	}
	res, err := wc.Enroll(ctx, &pantherclawv1.EnrollRequest{EnrollmentToken: tok.GetToken(), PublicJwk: string(jwk)})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	e.kf.Identifier, e.kf.Server = res.GetIdentifier(), s.server
	if err := workloadclient.WriteKeyFile(e.path, e.kf, true); err != nil {
		return err
	}
	if res.GetState() != pantherclawv1.InstanceState_INSTANCE_STATE_ADMITTED {
		if res.GetFingerprint() != e.fingerprint {
			return fmt.Errorf("PantherClaw enrolled instance %s with the fingerprint %s, not this key's %s; it was not admitted",
				res.GetInstanceId(), res.GetFingerprint(), e.fingerprint)
		}
		if _, err := c.identity.AdmitInstance(ctx, &pantherclawv1.AdmitInstanceRequest{Id: res.GetInstanceId(), Fingerprint: e.fingerprint}); err != nil {
			return fmt.Errorf("admitting instance %s: %w", res.GetInstanceId(), err)
		}
	}
	_, err = fmt.Fprintf(a.stdout, "Enrolled and admitted instance %s of agent %s; its key is in %s.\n", res.GetInstanceId(), e.agent, e.path)
	return err
}
