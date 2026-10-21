// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package helmchart renders deploy/helm/pantherclaw with the pinned helm
// (tools/pins/helm) and checks what it would deploy (G0 M13 D36, D42).
package helmchart

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/server"
)

var root = filepath.Join("..", "..")

var (
	helmOnce sync.Once
	helmBin  string
	helmErr  error
)

// helm builds the pinned helm once per test binary.
func helm(t *testing.T) string {
	t.Helper()
	helmOnce.Do(func() {
		modfile, err := filepath.Abs(filepath.Join(root, "tools", "pins", "helm", "go.mod"))
		if err != nil {
			helmErr = err
			return
		}
		dir, err := os.MkdirTemp("", "pantherclaw-helm")
		if err != nil {
			helmErr = err
			return
		}
		helmBin = filepath.Join(dir, "helm")
		if runtime.GOOS == "windows" {
			helmBin += ".exe"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		out, err := exec.CommandContext(ctx, "go", "build", "-modfile="+modfile, "-o", helmBin, "helm.sh/helm/v4/cmd/helm").CombinedOutput() //nolint:gosec // G204: the pinned helm
		if err != nil {
			helmErr = errors.New(string(out))
		}
	})
	if helmErr != nil {
		t.Fatalf("build the pinned helm: %v", helmErr)
	}
	return helmBin
}

// render runs helm template with the given --set values.
func render(t *testing.T, set ...string) []map[string]any {
	t.Helper()
	chart, err := filepath.Abs(filepath.Join(root, "deploy", "helm", "pantherclaw"))
	if err != nil {
		t.Fatal(err)
	}
	bin := helm(t)
	args := []string{"template", "pc", chart}
	for _, s := range set {
		args = append(args, "--set", s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: the pinned helm on the repository's chart
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template: %v\n%s", err, errb.String())
	}
	var docs []map[string]any
	dec := yaml.NewDecoder(&out)
	for {
		var d map[string]any
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
	return docs
}

func m(v any) map[string]any { r, _ := v.(map[string]any); return r }
func l(v any) []any          { r, _ := v.([]any); return r }

func get(v any, path ...string) any {
	for _, p := range path {
		v = m(v)[p]
	}
	return v
}

func name(d map[string]any) string {
	return d["kind"].(string) + "/" + get(d, "metadata", "name").(string)
}

// podSpecs returns the pod templates of every Deployment and Job.
func podSpecs(docs []map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, d := range docs {
		switch d["kind"] {
		case "Deployment", "Job":
			out[name(d)] = m(get(d, "spec", "template", "spec"))
		}
	}
	return out
}

func containers(spec map[string]any) []map[string]any {
	var out []map[string]any
	for _, c := range append(l(spec["initContainers"]), l(spec["containers"])...) {
		out = append(out, m(c))
	}
	return out
}

// TestHR398_ChartDefaultsAreHardened: with the default values every pod
// runs as non-root without a service account token, and every container,
// the init containers included, has a read-only root file system, no
// privilege escalation and drops every capability.
func TestHR398_ChartDefaultsAreHardened(t *testing.T) {
	docs := render(t)
	pods := podSpecs(docs)
	for _, want := range []string{"Deployment/pc-pantherclaw-api", "Deployment/pc-pantherclaw-worker", "Job/pc-pantherclaw-migrate"} {
		if pods[want] == nil {
			t.Fatalf("no %s in %v", want, pods)
		}
	}
	for pod, spec := range pods {
		if get(spec, "securityContext", "runAsNonRoot") != true {
			t.Errorf("%s: pod runAsNonRoot is not true", pod)
		}
		if spec["automountServiceAccountToken"] != false {
			t.Errorf("%s: mounts a service account token", pod)
		}
		for _, c := range containers(spec) {
			sc := m(c["securityContext"])
			at := pod + " " + c["name"].(string)
			if sc["runAsNonRoot"] != true {
				t.Errorf("%s: runAsNonRoot %v", at, sc["runAsNonRoot"])
			}
			if sc["readOnlyRootFilesystem"] != true {
				t.Errorf("%s: readOnlyRootFilesystem %v", at, sc["readOnlyRootFilesystem"])
			}
			if sc["allowPrivilegeEscalation"] != false {
				t.Errorf("%s: allowPrivilegeEscalation %v", at, sc["allowPrivilegeEscalation"])
			}
			if drop := l(get(sc, "capabilities", "drop")); len(drop) != 1 || drop[0] != "ALL" {
				t.Errorf("%s: capabilities.drop %v", at, drop)
			}
			if add := get(sc, "capabilities", "add"); add != nil {
				t.Errorf("%s: adds capabilities %v", at, add)
			}
			if sc["privileged"] == true {
				t.Errorf("%s: privileged", at)
			}
		}
	}
}

// TestChart_SecretsAreStagedInMemory: every pod stages its secrets with
// `secrets stage` from the server image into an in-memory emptyDir, from
// single keys mounted read-only with subPath (regular files, D42); the
// application containers mount the staged directory read-only and nothing
// else of the Secrets; only the migrate Job sees the migrator's password.
func TestChart_SecretsAreStagedInMemory(t *testing.T) {
	for pod, spec := range podSpecs(render(t)) {
		var stage map[string]any
		for _, c := range l(spec["initContainers"]) {
			if m(c)["name"] == "stage-secrets" {
				stage = m(c)
			}
		}
		if stage == nil {
			t.Errorf("%s: no stage-secrets init container", pod)
			continue
		}
		if args := l(stage["args"]); len(args) < 2 || args[0] != "secrets" || args[1] != "stage" {
			t.Errorf("%s: stage-secrets runs %v", pod, args)
		}
		volumes := map[string]map[string]any{}
		for _, v := range l(spec["volumes"]) {
			volumes[m(v)["name"].(string)] = m(v)
		}
		if get(volumes["secrets"], "emptyDir", "medium") != "Memory" {
			t.Errorf("%s: the staged secrets are not in memory: %v", pod, volumes["secrets"])
		}
		secretVolumes := map[string]bool{}
		for n, v := range volumes {
			if v["secret"] != nil {
				secretVolumes[n] = true
			}
		}
		for _, vm := range l(stage["volumeMounts"]) {
			mm := m(vm)
			if secretVolumes[mm["name"].(string)] && (mm["subPath"] == nil || mm["readOnly"] != true) {
				t.Errorf("%s: stage-secrets mounts %v without subPath, read-only", pod, mm)
			}
		}
		for _, c := range l(spec["containers"]) {
			for _, vm := range l(m(c)["volumeMounts"]) {
				mm := m(vm)
				n := mm["name"].(string)
				if secretVolumes[n] {
					t.Errorf("%s %s: mounts the Secret volume %s itself", pod, m(c)["name"], n)
				}
				if n == "secrets" && mm["readOnly"] != true {
					t.Errorf("%s %s: the staged secrets are writable", pod, m(c)["name"])
				}
			}
		}
		migrator := slices.ContainsFunc(l(spec["volumes"]), func(v any) bool {
			return get(v, "secret", "secretName") == "pantherclaw-database-migrator"
		})
		if migrator != strings.HasPrefix(pod, "Job/") {
			t.Errorf("%s: migrator password mounted = %v", pod, migrator)
		}
	}
}

// TestChart_MaintenanceHoldOnEveryReplica: maintenanceHold reaches every
// API and worker container (each process holds on its own; platform-3
// review L1), and is off by default.
func TestChart_MaintenanceHoldOnEveryReplica(t *testing.T) {
	for _, tc := range []struct {
		set  []string
		want string
	}{{nil, "false"}, {[]string{"maintenanceHold=true"}, "true"}} {
		pods := podSpecs(render(t, tc.set...))
		for _, pod := range []string{"Deployment/pc-pantherclaw-api", "Deployment/pc-pantherclaw-worker"} {
			for _, c := range l(pods[pod]["containers"]) {
				got := ""
				for _, e := range l(m(c)["env"]) {
					if m(e)["name"] == "PC_MAINTENANCE_HOLD" {
						got = m(e)["value"].(string)
					}
				}
				if got != tc.want {
					t.Errorf("%v: %s PC_MAINTENANCE_HOLD = %q, want %q", tc.set, pod, got, tc.want)
				}
			}
		}
	}
}

// TestChart_ServerConfigsValidate: the server.json of the API, the worker
// and the migrate Job load into the server's configuration and pass its
// validation; the worker serves its probes on health.addr (HR-397) and its
// probes point there.
func TestChart_ServerConfigsValidate(t *testing.T) {
	docs := render(t, "oidc.providers[0].name=sso", "oidc.providers[0].issuer=https://idp.example.com",
		"oidc.providers[0].clientID=pantherclaw", "oidc.providers[0].existingSecret=pantherclaw-oidc")
	roles := map[string]string{"ConfigMap/pc-pantherclaw-api": "api", "ConfigMap/pc-pantherclaw-worker": "worker", "ConfigMap/pc-pantherclaw-migrate": "api"}
	seen := 0
	for _, d := range docs {
		role, ok := roles[name(d)]
		if !ok {
			continue
		}
		seen++
		p := filepath.Join(t.TempDir(), "server.json")
		if err := os.WriteFile(p, []byte(get(d, "data", "server.json").(string)), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := server.DefaultConfig()
		if err := config.Load(&cfg, p, func(string) (string, bool) { return "", false }); err != nil {
			t.Fatalf("%s: %v", name(d), err)
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("%s: %v", name(d), err)
		}
		if cfg.Role != role || cfg.Deployment != "production" || cfg.DB.SSLMode != "verify-full" {
			t.Errorf("%s: role %s, deployment %s, sslmode %s", name(d), cfg.Role, cfg.Deployment, cfg.DB.SSLMode)
		}
		if (name(d) == "ConfigMap/pc-pantherclaw-worker") != (cfg.Health.Addr == "0.0.0.0:8081") {
			t.Errorf("%s: health.addr %q", name(d), cfg.Health.Addr)
		}
		if name(d) == "ConfigMap/pc-pantherclaw-api" && len(cfg.Auth.OIDCProviders) != 1 {
			t.Errorf("api: providers %v", cfg.Auth.OIDCProviders)
		}
	}
	if seen != 3 {
		t.Fatalf("found %d server configurations, want 3", seen)
	}
	worker := podSpecs(docs)["Deployment/pc-pantherclaw-worker"]
	c := m(l(worker["containers"])[0])
	if get(c, "readinessProbe", "httpGet", "port") != "health" || get(c, "readinessProbe", "httpGet", "path") != "/readyz" {
		t.Errorf("worker readiness probe %v", c["readinessProbe"])
	}
}
