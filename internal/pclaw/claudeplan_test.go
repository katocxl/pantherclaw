// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// TestHR208_InitChangesNothingUntilConfirmed: init shows the diff and asks;
// no, or no answer at all, changes nothing; --yes changes without asking;
// and --dry-run with --yes is refused.
func TestHR208_InitChangesNothingUntilConfirmed(t *testing.T) {
	for _, answer := range []string{"n\n", "", "yes please\n"} {
		f := newInitFixture(t)
		f.answer = answer
		code, out, errs := f.run(t)
		if _, err := os.Stat(f.local()); code != 1 || err == nil || !strings.Contains(out, "+++ ") || !strings.Contains(out, "[y/N]") ||
			!strings.Contains(errs, "not confirmed") {
			t.Errorf("answer %q: %d %s %s", answer, code, out, errs)
		}
	}
	f := newInitFixture(t)
	f.answer = ""
	if code, out, errs := f.run(t, "--yes"); code != 0 || !hookRunsIn(t, f.local()) || strings.Contains(out, "[y/N]") {
		t.Errorf("--yes: %d %s %s", code, out, errs)
	}
	if code, _, _ := f.run(t, "--yes", "--dry-run"); code == 0 {
		t.Error("--yes with --dry-run")
	}
}

// fakeEnrollment is the server side of enrolling as the signed-in person:
// it issues an enrollment token, enrolls a workload with it and admits an
// instance, answering the fingerprint of the key it was sent unless told
// another.
type fakeEnrollment struct {
	pantherclawv1connect.UnimplementedIdentityServiceHandler
	pantherclawv1connect.UnimplementedWorkloadServiceHandler
	mu          sync.Mutex
	fingerprint string
	issued      *pantherclawv1.CreateEnrollmentTokenRequest
	enrolled    *pantherclawv1.EnrollRequest
	admitted    *pantherclawv1.AdmitInstanceRequest
	// admitting, when set, runs while the instance is admitted, as Claude
	// Code may change a settings file during init's calls.
	admitting func()
}

// fakeEnrollmentToken is built at run time, so no token-like literal sits
// in the source (task secrets).
var fakeEnrollmentToken = "pce_test_" + strings.Repeat("0a", 8)

func (f *fakeEnrollment) CreateEnrollmentToken(_ context.Context, req *pantherclawv1.CreateEnrollmentTokenRequest) (
	*pantherclawv1.CreateEnrollmentTokenResponse, error,
) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued = req
	return &pantherclawv1.CreateEnrollmentTokenResponse{Id: "tok-1", Token: fakeEnrollmentToken}, nil
}

func (f *fakeEnrollment) Enroll(_ context.Context, req *pantherclawv1.EnrollRequest) (*pantherclawv1.EnrollResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrolled = req
	var jwk struct {
		X string `json:"x"`
	}
	_ = json.Unmarshal([]byte(req.GetPublicJwk()), &jwk)
	pub, _ := base64.RawURLEncoding.DecodeString(jwk.X)
	fp := jws.Thumbprint(ed25519.PublicKey(pub))
	if f.fingerprint != "" {
		fp = f.fingerprint
	}
	return &pantherclawv1.EnrollResponse{
		InstanceId: "inst-1", Identifier: "pc:org/o/agent/a/inst/inst-1", Fingerprint: fp,
		State: pantherclawv1.InstanceState_INSTANCE_STATE_PENDING_ADMISSION,
	}, nil
}

func (f *fakeEnrollment) AdmitInstance(_ context.Context, req *pantherclawv1.AdmitInstanceRequest) (*pantherclawv1.AdmitInstanceResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.admitted = req
	if f.admitting != nil {
		f.admitting()
	}
	return &pantherclawv1.AdmitInstanceResponse{}, nil
}

// enrollmentServer serves the fake and signs init in with an API key.
func (f *initFixture) enrollmentServer(t *testing.T, fake *fakeEnrollment) string {
	t.Helper()
	cs := connect.NewServer()
	pantherclawv1connect.RegisterIdentityServiceHandler(cs, fake)
	pantherclawv1connect.RegisterWorkloadServiceHandler(cs, fake)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	f.env["PANTHERCLAW_SERVER"], f.env["PANTHERCLAW_API_KEY"] = ts.URL, "pck_test_x"
	f.key = filepath.Join(filepath.Dir(f.key), "new-workload.json")
	return ts.URL
}

// TestHR208_InitEnrollsAsTheSignedInPerson: without an enrolled key file
// init needs --agent; a dry run creates nothing and calls nothing; then it
// creates the key (0600), enrolls it with an enrollment token issued to
// the signed-in person and used at once, and admits it with the
// fingerprint it showed before asking (HR-094). The token is written
// nowhere, and a second run changes nothing.
func TestHR208_InitEnrollsAsTheSignedInPerson(t *testing.T) {
	const agent = "0192aaaa-bbbb-7ccc-8ddd-000000000001"
	f := newInitFixture(t)
	fake := &fakeEnrollment{}
	server := f.enrollmentServer(t, fake)
	if code, _, errs := f.run(t); code == 0 || !strings.Contains(errs, "--agent") {
		t.Fatalf("no agent: %d %s", code, errs)
	}
	if code, _, _ := f.run(t, "--agent", "coder"); code == 0 {
		t.Fatal("an agent that is not an id")
	}
	code, out, errs := f.run(t, "--agent", agent, "--dry-run")
	if _, err := os.Stat(f.key); code != 0 || err == nil || fake.issued != nil || !strings.Contains(out, "Enroll a new workload key") {
		t.Fatalf("dry run: %d %s %s", code, out, errs)
	}
	code, out, errs = f.run(t, "--agent", agent)
	if code != 0 {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
	kf, err := workloadclient.ReadKeyFile(f.key)
	if err != nil || kf.Identifier != "pc:org/o/agent/a/inst/inst-1" || kf.Server != server {
		t.Fatalf("key file %+v %v", kf, err)
	}
	if st, err := os.Stat(f.key); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Fatalf("key file mode: %v %v", st, err)
	}
	key, _ := kf.Key()
	fp := jws.Thumbprint(key.Public().(ed25519.PublicKey))
	if fake.issued.GetAgentId() != agent || fake.enrolled.GetEnrollmentToken() != fakeEnrollmentToken ||
		fake.admitted.GetId() != "inst-1" || fake.admitted.GetFingerprint() != fp {
		t.Fatalf("requests: %v %v %v", fake.issued, fake.enrolled, fake.admitted)
	}
	if i, j := strings.Index(out, fp), strings.Index(out, "[y/N]"); i < 0 || j < i {
		t.Fatalf("the fingerprint was not shown before asking:\n%s", out)
	}
	for _, p := range []string{f.key, f.local()} {
		if b, _ := os.ReadFile(p); strings.Contains(string(b), fakeEnrollmentToken) {
			t.Errorf("%s holds the enrollment token", p)
		}
	}
	if !hookRunsIn(t, f.local()) {
		t.Fatal("no hook")
	}
	fake.issued = nil
	if code, out, _ := f.run(t, "--agent", agent); code != 0 || !strings.Contains(out, "Nothing to change.") || fake.issued != nil {
		t.Fatalf("second run: %d %s", code, out)
	}
}

// TestHR208_InitAdmitsOnlyTheKeyItShowed: when the server enrolled a key
// with another fingerprint, nothing is admitted and the settings are left
// as they are.
func TestHR208_InitAdmitsOnlyTheKeyItShowed(t *testing.T) {
	f := newInitFixture(t)
	fake := &fakeEnrollment{fingerprint: "someone-elses-key"}
	f.enrollmentServer(t, fake)
	code, out, errs := f.run(t, "--agent", "0192aaaa-bbbb-7ccc-8ddd-000000000001")
	if _, err := os.Stat(f.local()); code == 0 || fake.admitted != nil || err == nil || !strings.Contains(errs, "not admitted") {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
}

// answerAfterChanging answers yes at init's prompt after writing a file,
// as Claude Code may while the person reads the diff.
type answerAfterChanging struct {
	t             *testing.T
	path, content string
	answered      bool
}

func (r *answerAfterChanging) Read(p []byte) (int, error) {
	if r.answered {
		return 0, io.EOF
	}
	r.answered = true
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		r.t.Error(err)
	}
	if err := os.WriteFile(r.path, []byte(r.content), 0o600); err != nil {
		r.t.Error(err)
	}
	return copy(p, "y\n"), nil
}

// TestHR208_InitWritesNothingWhenAFileChangedMeanwhile: a settings file
// that changed between init reading it and the person confirming (Claude
// Code added a deny rule to it, or created it) is not overwritten: init
// fails, writes and backs up nothing, and says to run it again, which
// keeps the change.
func TestHR208_InitWritesNothingWhenAFileChangedMeanwhile(t *testing.T) {
	added := strings.Replace(existingLocal, `"Read(./.env)"`, "\"Read(./.env)\",\n      \"Bash(rm:*)\"", 1)
	for name, before := range map[string]string{"changed": existingLocal, "created": ""} {
		f := newInitFixture(t)
		if before != "" {
			f.write(t, f.local(), before)
		}
		f.stdin = &answerAfterChanging{t: t, path: f.local(), content: added}
		code, out, errs := f.run(t)
		if now, _ := os.ReadFile(f.local()); code != 1 || string(now) != added || !strings.Contains(out, "[y/N]") ||
			!strings.Contains(errs, "changed after init read it") || !strings.Contains(errs, "run pclaw init again") {
			t.Errorf("%s: %d %s %s", name, code, out, errs)
		}
		if len(backups(t, f.local())) != 0 {
			t.Errorf("%s: backed up", name)
		}
		f.stdin = nil
		code, out, errs = f.run(t)
		perm, _ := readJSON(t, f.local())["permissions"].(map[string]any)
		deny, _ := perm["deny"].([]any)
		if code != 0 || !hookRunsIn(t, f.local()) || len(deny) != 3 || deny[2] != "Bash(rm:*)" {
			t.Errorf("%s, run again: %d %s %s", name, code, out, errs)
		}
	}
}

// TestHR208_InitEnrollsNothingWhenAFileChangedMeanwhile: a settings file
// that changed while the person read the plan stops the enrollment too:
// no enrollment token is asked for and no key file is written.
func TestHR208_InitEnrollsNothingWhenAFileChangedMeanwhile(t *testing.T) {
	f := newInitFixture(t)
	fake := &fakeEnrollment{}
	f.enrollmentServer(t, fake)
	f.write(t, f.local(), existingLocal)
	f.stdin = &answerAfterChanging{t: t, path: f.local(), content: existingLocal + "\n"}
	code, out, errs := f.run(t, "--agent", "0192aaaa-bbbb-7ccc-8ddd-000000000001")
	if _, err := os.Stat(f.key); code != 1 || err == nil || fake.issued != nil || !strings.Contains(errs, "run pclaw init again") {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
}

// TestHR208_InitSaysTheKeyIsEnrolledWhenAFileChangedDuringEnrollment: a
// settings file that changed while init was enrolling is left as it is,
// and init fails saying what is true then: the key is enrolled and
// admitted, no settings file was written, and init should run again,
// which writes the hook and enrolls nothing more.
func TestHR208_InitSaysTheKeyIsEnrolledWhenAFileChangedDuringEnrollment(t *testing.T) {
	const agent = "0192aaaa-bbbb-7ccc-8ddd-000000000001"
	added := strings.Replace(existingLocal, `"Read(./.env)"`, "\"Read(./.env)\",\n      \"Bash(rm:*)\"", 1)
	f := newInitFixture(t)
	fake := &fakeEnrollment{}
	f.enrollmentServer(t, fake)
	f.write(t, f.local(), existingLocal)
	fake.admitting = func() {
		if err := os.WriteFile(f.local(), []byte(added), 0o600); err != nil {
			t.Error(err)
		}
	}
	code, out, errs := f.run(t, "--agent", agent)
	now, _ := os.ReadFile(f.local())
	if code != 1 || string(now) != added || len(backups(t, f.local())) != 0 || fake.admitted == nil ||
		!strings.Contains(errs, "changed after init read it") || !strings.Contains(errs, "the key in "+f.key+" is enrolled and admitted") ||
		!strings.Contains(errs, "no settings file was written") || !strings.Contains(errs, "run pclaw init again") ||
		strings.Contains(errs, "nothing was changed") {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
	if kf, err := workloadclient.ReadKeyFile(f.key); err != nil || kf.Identifier == "" {
		t.Fatalf("the key is not enrolled: %+v %v", kf, err)
	}
	fake.issued, fake.admitting = nil, nil
	code, out, errs = f.run(t, "--agent", agent)
	perm, _ := readJSON(t, f.local())["permissions"].(map[string]any)
	if deny, _ := perm["deny"].([]any); code != 0 || !hookRunsIn(t, f.local()) || len(deny) != 3 || fake.issued != nil {
		t.Fatalf("run again: %d %s %s", code, out, errs)
	}
}

// TestHR208_InitRefusesAKeyFileOthersCanRead:a key file that is not
// enrolled yet is rewritten in place with its identifier, so one other
// users can read is refused before anything is done, and keeps its mode;
// once it is 0600 init enrolls it.
func TestHR208_InitRefusesAKeyFileOthersCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are POSIX")
	}
	f := newInitFixture(t)
	fake := &fakeEnrollment{}
	f.enrollmentServer(t, fake)
	kf, _, err := workloadclient.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	if err := workloadclient.WriteKeyFile(f.key, kf, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.key, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errs := f.run(t, "--agent", "0192aaaa-bbbb-7ccc-8ddd-000000000001")
	st, _ := os.Stat(f.key)
	if _, err := os.Stat(f.local()); code == 0 || err == nil || fake.issued != nil || !strings.Contains(errs, "other users can read") ||
		st == nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
	if err := os.Chmod(f.key, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := f.run(t, "--agent", "0192aaaa-bbbb-7ccc-8ddd-000000000001"); code != 0 || fake.admitted == nil {
		t.Fatalf("init with a 0600 key file: %d %s %s", code, out, errs)
	}
}

// TestHR094_InitWithYesNeedsTheFingerprintYouChecked: with --yes no one is
// asked, so enrolling needs --fingerprint, the key's own: without it, with
// another, or for a key init would create (which has none to check yet),
// init fails before anything is asked of the server or written; with it,
// init enrolls and admits that key.
func TestHR094_InitWithYesNeedsTheFingerprintYouChecked(t *testing.T) {
	const agent = "0192aaaa-bbbb-7ccc-8ddd-000000000001"
	f := newInitFixture(t)
	fake := &fakeEnrollment{}
	f.enrollmentServer(t, fake)
	kf, key, err := workloadclient.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	if err := workloadclient.WriteKeyFile(f.key, kf, false); err != nil {
		t.Fatal(err)
	}
	onlyTheUserReads(t, f.key)
	fp := jws.Thumbprint(key.Public().(ed25519.PublicKey))
	existing := f.key
	for name, tc := range map[string]struct {
		key  string
		args []string
		want string
	}{
		"no fingerprint":      {key: existing, want: "needs --fingerprint"},
		"another fingerprint": {key: existing, args: []string{"--fingerprint", "someone-elses-key"}, want: "is not the fingerprint"},
		"a key to create":     {key: filepath.Join(filepath.Dir(existing), "new.json"), args: []string{"--fingerprint", fp}, want: "create it first"},
	} {
		f.key = tc.key
		code, out, errs := f.run(t, append([]string{"--agent", agent, "--yes"}, tc.args...)...)
		if _, err := os.Stat(f.local()); code == 0 || err == nil || fake.issued != nil || !strings.Contains(errs, tc.want) {
			t.Errorf("%s: %d %s %s", name, code, out, errs)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(existing), "new.json")); err == nil {
			t.Errorf("%s: a key file was created", name)
		}
	}
	f.key = existing
	code, out, errs := f.run(t, "--agent", agent, "--yes", "--fingerprint", fp)
	if code != 0 || fake.admitted.GetFingerprint() != fp || !hookRunsIn(t, f.local()) || strings.Contains(out, "[y/N]") {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
}
