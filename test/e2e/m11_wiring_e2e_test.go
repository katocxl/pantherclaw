// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// m11Files are the proto files M11 part 2 added or extended: every
// procedure in them is served by the real server.
var m11Files = []protoreflect.FileDescriptor{
	pantherclawv1.File_pantherclaw_v1_automations_proto,
	pantherclawv1.File_pantherclaw_v1_changes_proto,
	pantherclawv1.File_pantherclaw_v1_automation_triggers_proto,
	pantherclawv1.File_pantherclaw_v1_automation_executions_proto,
	pantherclawv1.File_pantherclaw_v1_automation_assurance_proto,
	pantherclawv1.File_pantherclaw_v1_automation_templates_proto,
	pantherclawv1.File_pantherclaw_v1_promotions_proto,
	pantherclawv1.File_pantherclaw_v1_cohorts_proto,
	pantherclawv1.File_pantherclaw_v1_packs_proto,
	pantherclawv1.File_pantherclaw_v1_protected_changes_proto,
	pantherclawv1.File_pantherclaw_v1_search_proto,
	pantherclawv1.File_pantherclaw_v1_exposure_proto,
	pantherclawv1.File_pantherclaw_v1_evidence_proto,
	pantherclawv1.File_pantherclaw_v1_agents_proto,
	pantherclawv1.File_pantherclaw_v1_operations_proto,
}

// TestE2E_M11_EveryProcedureIsServed: on the real (Community) server every
// M11 part 2 procedure answers something other than Unimplemented, so no
// service is left unwired (G0 M11 part 2 D96). An empty request is refused
// by validation, the permission check or the edition (EDITION_REQUIRED is
// fine); only "unimplemented" or an unrouted path fails.
func TestE2E_M11_EveryProcedureIsServed(t *testing.T) {
	r := startReflex(t)
	// Alice holds every role at the org, so no permission check stands in
	// front of a handler.
	for _, role := range everyRole {
		if code, o, e := r.alice.pclaw(t, "role", "bind", "--role", role, "--user", r.aliceID.String()); code != 0 && !strings.Contains(e, "ROLE_BINDING_EXISTS") && !strings.Contains(e, "SCOPE_NOT_ALLOWED") {
			t.Fatalf("role bind %s: %d %s %s", role, code, o, e)
		}
	}
	r.alice.login(t, r.s.org.String(), "")
	hc := &http.Client{Timeout: 30 * time.Second, Transport: keyBearer{bearerOf(t, r.alice)}}
	n, masked := 0, 0
	for _, f := range m11Files {
		ss := f.Services()
		for i := range ss.Len() {
			svc := ss.Get(i)
			ms := svc.Methods()
			for j := range ms.Len() {
				m := ms.Get(j)
				procedure := "/" + string(svc.FullName()) + "/" + string(m.Name())
				n++
				streaming := m.IsStreamingServer() || m.IsStreamingClient()
				code, why := call(t, hc, r.s.apiURL, procedure, streaming, []byte("{}"))
				if code == "invalid_argument" {
					// Validation runs before the handler: try a request with
					// every field set.
					code, why = call(t, hc, r.s.apiURL, procedure, streaming, filled(t, m.Input()))
				}
				switch code {
				case "unimplemented":
					t.Errorf("%s is not served: %s", procedure, why)
				case "invalid_argument", "permission_denied":
					// A handler's own refusal names its code; request
					// validation and the procedure's permission do not.
					if !strings.HasPrefix(why, "invalid request:") && !strings.HasPrefix(why, "PERMISSION_DENIED: missing permission") {
						break
					}
					masked++
					t.Logf("%s: refused before its handler (%s)", procedure, why)
				}
			}
		}
	}
	if n < 100 {
		t.Fatalf("only %d procedures checked", n)
	}
	t.Logf("%d procedures, %d refused before their handler (TestM11_WiringComplete checks those handlers)", n, masked)
}

// call calls a procedure with a JSON request over the Connect protocol and returns the error code ("" for success) and its message.
func call(t *testing.T, hc *http.Client, base, procedure string, streaming bool, msg []byte) (string, string) {
	t.Helper()
	body, ctype := msg, "application/json"
	if streaming {
		// One enveloped message: flags 0, the length, the JSON.
		n := len(msg)
		body = append([]byte{0, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, msg...)
		ctype = "application/connect+json"
	}
	req, err := http.NewRequest(http.MethodPost, base+procedure, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Connect-Protocol-Version", "1")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", procedure, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if streaming {
		// The end-of-stream message carries the error, if any.
		for len(out) >= 5 {
			size := int(out[1])<<24 | int(out[2])<<16 | int(out[3])<<8 | int(out[4])
			if 5+size > len(out) {
				break
			}
			if out[0]&2 != 0 {
				var end struct {
					Error *struct {
						Code    string `json:"code"`
						Message string `json:"message"`
					} `json:"error"`
				}
				if json.Unmarshal(out[5:5+size], &end) == nil && end.Error != nil {
					return end.Error.Code, end.Error.Message
				}
				return "", ""
			}
			out = out[5+size:]
		}
	}
	if resp.StatusCode == http.StatusOK {
		return "", ""
	}
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(out, &e) != nil || e.Code == "" {
		// Not a Connect error: the path is not routed at all.
		return "unimplemented", resp.Status + " " + string(out)
	}
	return e.Code, e.Message
}

// everyRole is every role a person can hold; those that cannot be bound at the org are
// skipped.
var everyRole = []string{
	"org_admin", "security_admin", "agent_owner", "policy_author", "policy_publisher", "approver", "responder", "auditor",
	"developer", "viewer", "run_launcher", "agent_admitter", "identity_publisher", "grant_issuer", "fact_provider",
	"gateway_admin", "emergency_responder", "reconciler", "records_manager", "code_reviewer", "release_approver",
	"automation_author", "automation_publisher", "automation_operator", "fleet_manager",
}

// filled is a request of type md with every singular field set to a
// plausible value (ids as fresh UUIDs, enums to their first named value
// after UNSPECIFIED), two levels deep, as JSON.
func filled(t *testing.T, md protoreflect.MessageDescriptor) []byte {
	t.Helper()
	b, err := protojson.Marshal(fill(md, 0))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fill(md protoreflect.MessageDescriptor, depth int) *dynamicpb.Message {
	m := dynamicpb.NewMessage(md)
	if depth > 2 || strings.HasPrefix(string(md.FullName()), "google.protobuf.") {
		return m
	}
	fs := md.Fields()
	seen := map[protoreflect.FullName]bool{}
	for i := range fs.Len() {
		f := fs.Get(i)
		if f.IsList() || f.IsMap() {
			continue
		}
		if o := f.ContainingOneof(); o != nil && !o.IsSynthetic() {
			if seen[o.FullName()] {
				continue
			}
			seen[o.FullName()] = true
		}
		var v protoreflect.Value
		switch f.Kind() { //exhaustive:ignore // the rest keep their zero value
		case protoreflect.StringKind:
			s := "x"
			if name := string(f.Name()); name == "id" || strings.HasSuffix(name, "_id") {
				s = ids.NewV7().String()
			}
			v = protoreflect.ValueOfString(s)
		case protoreflect.BoolKind:
			v = protoreflect.ValueOfBool(true)
		case protoreflect.Int32Kind, protoreflect.Sint32Kind:
			v = protoreflect.ValueOfInt32(1)
		case protoreflect.Int64Kind, protoreflect.Sint64Kind:
			v = protoreflect.ValueOfInt64(1)
		case protoreflect.Uint32Kind:
			v = protoreflect.ValueOfUint32(1)
		case protoreflect.Uint64Kind:
			v = protoreflect.ValueOfUint64(1)
		case protoreflect.EnumKind:
			vs := f.Enum().Values()
			if vs.Len() < 2 {
				continue
			}
			v = protoreflect.ValueOfEnum(vs.Get(1).Number())
		case protoreflect.MessageKind:
			v = protoreflect.ValueOfMessage(fill(f.Message(), depth+1))
		default:
			continue
		}
		m.Set(f, v)
	}
	return m
}
