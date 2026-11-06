// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	pcazurecompute "github.com/katocxl/pantherclaw/packages/pc-azure-compute"
)

// TestHR760_RuntimeCallsMapThroughTheMCPMappings: a cloud agent runtime's
// tool call maps through the reviewed MCP mapping exactly as the MCP face's
// call does, except that the channel is runtime, stamped before
// canonicalization (G0 M34 D990); a hook mapping and an unknown tool are
// never reached through it, and input the mapping does not read is
// refused. A package mapping of its own on channel runtime is refused.
func TestHR760_RuntimeCallsMapThroughTheMCPMappings(t *testing.T) {
	ctx := context.Background()
	payments := mapperFor(t, mockRaw(t))
	const refund = `{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`
	got, err := payments.Runtime(ctx, tc, "create_refund", []byte(refund))
	if err != nil {
		t.Fatal(err)
	}
	direct, err := payments.MCP(ctx, tc, "create_refund", []byte(refund))
	if err != nil {
		t.Fatal(err)
	}
	a := direct.Action
	a.Channel = string(domain.ChannelRuntime)
	want, err := actionir.Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	if got.Action.Channel != "runtime" || !bytes.Equal(got.Canonical, want.Canonical) || got.HashHex() == direct.HashHex() {
		t.Fatalf("runtime %s, want %s", got.Canonical, want.Canonical)
	}
	shell := shellMapper(t)
	for name, err := range map[string]error{
		"the shell":     second(shell.Runtime(ctx, tc, "shell", []byte(hookInput("bash", "ls", "/x", "t1")))),
		"an unknown":    second(payments.Runtime(ctx, tc, "delete_everything", []byte(`{}`))),
		"unknown input": second(payments.Runtime(ctx, tc, "get_refund", []byte(`{"refund":"re_1","x":"y"}`))),
	} {
		want := ErrUnmapped
		if name == "unknown input" {
			want = actionir.ErrAmbiguous
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}

	p, err := manifest.Decode(mockRaw(t))
	if err != nil {
		t.Fatal(err)
	}
	edited := false
	for i := range p.Definitions {
		for j, m := range p.Definitions[i].Mappings {
			if m.Channel == domain.ChannelMCP && !edited {
				m.Channel, m.Description, m.InputSchema = domain.ChannelRuntime, "", nil
				p.Definitions[i].Mappings[j], edited = m, true
			}
		}
	}
	if err := p.Validate(); !edited || err == nil || !strings.Contains(err.Error(), "runtime channel maps through mcp mappings") {
		t.Fatalf("a runtime mapping: %v", err)
	}
}

// TestT348_AnAzureRunCommandIsOneVMAClosedCommandIdAndABoundedScript: an
// Azure VM run command maps to one VM (subscription/group/vm) with a
// command id from the closed enum and a script of at most 8192 bytes;
// another command id, a longer script, an unknown field or a VM name with
// a path are refused.
func TestT348_AnAzureRunCommandIsOneVMAClosedCommandIdAndABoundedScript(t *testing.T) {
	m := mapperFor(t, pcazurecompute.Package)
	const sub = "0f0e0d0c-0b0a-4908-8706-050403020100"
	call := func(cmd, script, vm, extra string) (actionir.Parsed, error) {
		args := `{"subscription_id":"` + sub + `","resource_group":"rg-1","vm_name":"` + vm + `","command_id":"` + cmd + `","script":` +
			strconvQuote(script) + extra + `}`
		return m.Runtime(context.Background(), tc, "azure_vm_run_command", []byte(args))
	}
	a, err := call("RunShellScript", strings.Repeat("x", 8192), "vm-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Action.Operation != "azure.vm.run_command" || a.Action.Target.ID != sub+"/rg-1/vm-1" || a.Action.Channel != "runtime" {
		t.Fatalf("mapped %+v", a.Action)
	}
	for name, err := range map[string]error{
		"other command id": second(call("RunCommand", "uptime", "vm-1", "")),
		"script too long":  second(call("RunShellScript", strings.Repeat("x", 8193), "vm-1", "")),
		"unknown field":    second(call("RunShellScript", "uptime", "vm-1", `,"run_as_user":"root"`)),
		"vm with a path":   second(call("RunShellScript", "uptime", "vm-1/../vm-2", "")),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
