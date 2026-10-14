// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sandbox

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
)

// TestHR216_TheAgentsChecksSeeItsBindsAndTheSocket: the agent's checks
// pass only when its binds are files of the session's directory and no
// mount names the engine's socket.
func TestHR216_TheAgentsChecksSeeItsBindsAndTheSocket(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	bind := func(src, target string) map[string]any {
		return map[string]any{"Type": "bind", "Source": src, "Target": target, "ReadOnly": true}
	}
	volume := map[string]any{"Type": "volume", "Source": "pc-ws-1", "Target": "/workspace"}
	for name, tc := range map[string]struct {
		mounts       []map[string]any
		socket, host bool
	}{
		"the CA and the workspace": {[]map[string]any{bind(ca, "/pc/ca/ca.pem"), volume}, true, true},
		"the session directory":    {[]map[string]any{bind(dir, "/pc/dir"), volume}, true, false},
		"a file outside it":        {[]map[string]any{bind(outside, "/pc/x"), volume}, true, false},
		"the socket":               {[]map[string]any{bind(ca, "/var/run/docker.sock")}, false, true},
	} {
		b, err := json.Marshal(map[string]any{"HostConfig": map[string]any{"Mounts": tc.mounts}})
		if err != nil {
			t.Fatal(err)
		}
		var info docker.ContainerInfo
		if err := json.Unmarshal(b, &info); err != nil {
			t.Fatal(err)
		}
		got := agentChecks(info, dir)
		if len(got) != 2 || got[0].ID != "agent_no_docker_socket" || got[0].OK != tc.socket || got[1].ID != "agent_no_host_bind" || got[1].OK != tc.host {
			t.Errorf("%s: %+v", name, got)
		}
	}
}
