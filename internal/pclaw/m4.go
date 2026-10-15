// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// M4 commands: grants and guardrails (Pass, Guardrails), facts, tool
// packages and policies. Bounds, requirements, limits, policy bundles and
// package files are read from files, never typed on the command line, and
// sent as they are: the server decodes them strictly (HR-100).

// maxDocument bounds a document read from a file (the API refuses more).
const maxDocument = 1 << 20

func init() {
	for k, v := range authorityCommands() {
		commands[k] = v
	}
}

var (
	grantStates = map[string]pantherclawv1.GrantState{
		"active": pantherclawv1.GrantState_GRANT_STATE_ACTIVE, "revoked": pantherclawv1.GrantState_GRANT_STATE_REVOKED,
	}
	scopeKinds = map[string]pantherclawv1.GuardrailScopeKind{
		"org": pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_ORG, "bu": pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_BUSINESS_UNIT,
		"team": pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_TEAM, "env": pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_ENVIRONMENT,
		"principal": pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_PRINCIPAL,
	}
	factTypes = map[string]pantherclawv1.FactType{
		"boolean": pantherclawv1.FactType_FACT_TYPE_BOOLEAN, "integer": pantherclawv1.FactType_FACT_TYPE_INTEGER,
		"decimal": pantherclawv1.FactType_FACT_TYPE_DECIMAL, "money": pantherclawv1.FactType_FACT_TYPE_MONEY,
		"identifier": pantherclawv1.FactType_FACT_TYPE_IDENTIFIER, "timestamp": pantherclawv1.FactType_FACT_TYPE_TIMESTAMP,
		"object": pantherclawv1.FactType_FACT_TYPE_OBJECT,
	}
	packageStates = map[string]pantherclawv1.PackageState{
		"draft": pantherclawv1.PackageState_PACKAGE_STATE_DRAFT, "reviewed": pantherclawv1.PackageState_PACKAGE_STATE_REVIEWED,
		"active": pantherclawv1.PackageState_PACKAGE_STATE_ACTIVE, "stale": pantherclawv1.PackageState_PACKAGE_STATE_STALE,
		"quarantined": pantherclawv1.PackageState_PACKAGE_STATE_QUARANTINED, "retired": pantherclawv1.PackageState_PACKAGE_STATE_RETIRED,
	}
)

// readDocument reads a JSON or package document from a file; an empty
// path is no document.
func readDocument(flagName, path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path) //nolint:gosec // G304: operator-chosen path
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", flagName, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxDocument+1))
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", flagName, err)
	}
	if len(b) > maxDocument {
		return nil, fmt.Errorf("--%s: the file is larger than %d bytes", flagName, maxDocument)
	}
	return b, nil
}

// actorOf parses "user:ID" or "service_account:ID".
func actorOf(flagName, s string) (*pantherclawv1.Actor, error) {
	kind, id, ok := strings.Cut(s, ":")
	if !ok || (kind != "user" && kind != "service_account") || id == "" {
		return nil, fmt.Errorf("--%s must be user:ID or service_account:ID", flagName)
	}
	return &pantherclawv1.Actor{Kind: kind, Id: id}, nil
}

// timeOf parses an RFC 3339 time or a duration from now ("48h"); empty is
// unset.
func timeOf(flagName, s string) (*timestamppb.Timestamp, error) {
	if s == "" {
		return nil, nil //nolint:nilnil // unset
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return timestamppb.New(time.Now().Add(d)), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, fmt.Errorf("--%s must be a duration such as 48h or an RFC 3339 time", flagName)
	}
	return timestamppb.New(t), nil
}

// scopeOf parses a guardrail scope: org, bu:ID, team:ID, env:ID,
// user:ID or service_account:ID.
func scopeOf(s string) (*pantherclawv1.GuardrailScope, error) {
	if s == "org" {
		return &pantherclawv1.GuardrailScope{Kind: pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_ORG}, nil
	}
	kind, id, ok := strings.Cut(s, ":")
	switch {
	case !ok || id == "":
	case kind == "user" || kind == "service_account":
		return &pantherclawv1.GuardrailScope{
			Kind: pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_PRINCIPAL, Principal: &pantherclawv1.Actor{Kind: kind, Id: id},
		}, nil
	case kind == "bu" || kind == "team" || kind == "env":
		return &pantherclawv1.GuardrailScope{Kind: scopeKinds[kind], Id: id}, nil
	}
	return nil, fmt.Errorf("--scope must be org, bu:ID, team:ID, env:ID, user:ID or service_account:ID")
}

// terms are the document flags of grants and guardrails.
type terms struct{ bounds, requirements, limits *string }

func termFlags(fs *flag.FlagSet) terms {
	return terms{
		bounds:       fs.String("bounds-file", "", "bounds (grant bounds v1, JSON)"),
		requirements: fs.String("requirements-file", "", "approval and step-up requirements (JSON array)"),
		limits:       fs.String("limits-file", "", "budget and count rules (JSON)"),
	}
}

func (t terms) read() (bounds, requirements, limits []byte, err error) {
	if *t.bounds == "" {
		return nil, nil, nil, fmt.Errorf("--bounds-file is required")
	}
	if bounds, err = readDocument("bounds-file", *t.bounds); err != nil {
		return nil, nil, nil, err
	}
	if requirements, err = readDocument("requirements-file", *t.requirements); err != nil {
		return nil, nil, nil, err
	}
	limits, err = readDocument("limits-file", *t.limits)
	return bounds, requirements, limits, err
}

// delegationFlags are the delegation settings of a grant.
func delegationFlags(fs *flag.FlagSet) (depth, children *int) {
	return fs.Int("delegation-depth", 0, "further levels it may be delegated (0: none, at most 4)"),
		fs.Int("max-children", 0, "most active delegated children at once (at most 50)")
}

func delegation(depth, children *int) *pantherclawv1.GrantDelegation {
	return &pantherclawv1.GrantDelegation{Depth: int32(min(max(*depth, 0), 4)), MaxChildren: int32(min(max(*children, 0), 50))}
}

func attestation(n *int) int32 { return int32(min(max(*n, 0), 2)) }

func authorityCommands() map[string]command {
	return map[string]command{
		"grant issue": rpc("grant issue AGENT --principal user:ID|service_account:ID --expires 48h|TIME --bounds-file FILE "+
			"[--requirements-file FILE] [--limits-file FILE] [--instance ID] [--task REF] [--start TIME] "+
			"[--delegation-depth N] [--max-children N] [--min-attestation 0-2]", 1, func(fs *flag.FlagSet) call {
			principal, expires, start := fs.String("principal", "", "who the agent acts for"), fs.String("expires", "", "valid until"),
				fs.String("start", "", "valid from (default: now)")
			inst, task := fs.String("instance", "", "only this admitted instance"), fs.String("task", "", "untrusted task label")
			docs := termFlags(fs)
			depth, children := delegationFlags(fs)
			minAtt := fs.Int("min-attestation", 0, "lowest workload attestation level that may use it")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				p, err := actorOf("principal", *principal)
				if err != nil {
					return nil, err
				}
				exp, err := timeOf("expires", *expires)
				if err != nil || exp == nil {
					return nil, fmt.Errorf("--expires must be a duration such as 48h or an RFC 3339 time")
				}
				from, err := timeOf("start", *start)
				if err != nil {
					return nil, err
				}
				b, r, l, err := docs.read()
				if err != nil {
					return nil, err
				}
				return c.grants.IssueGrant(ctx, &pantherclawv1.IssueGrantRequest{
					AgentId: a[0], InstanceId: optStr(*inst), Principal: p, TaskRef: *task, StartTime: from, ExpireTime: exp,
					Bounds: b, Requirements: r, Limits: l, Delegation: delegation(depth, children), MinAttestationLevel: attestation(minAtt),
				})
			}
		}),
		"grant revise": rpc("grant revise ID --revision N --bounds-file FILE [--requirements-file FILE] [--limits-file FILE] "+
			"[--expires 48h|TIME] [--task REF] [--delegation-depth N] [--max-children N] [--min-attestation 0-2]", 1, func(fs *flag.FlagSet) call {
			rev, expires, task := fs.Int("revision", 0, "the revision the change is based on"), fs.String("expires", "", "new expiry"),
				fs.String("task", "", "untrusted task label")
			docs := termFlags(fs)
			depth, children := delegationFlags(fs)
			minAtt := fs.Int("min-attestation", 0, "lowest workload attestation level that may use it")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				if *rev < 1 {
					return nil, fmt.Errorf("--revision is required (from grant get)")
				}
				exp, err := timeOf("expires", *expires)
				if err != nil {
					return nil, err
				}
				b, r, l, err := docs.read()
				if err != nil {
					return nil, err
				}
				return c.grants.ReviseGrant(ctx, &pantherclawv1.ReviseGrantRequest{
					Id: a[0], Revision: int32(min(*rev, 1<<30)), TaskRef: *task, ExpireTime: exp,
					Bounds: b, Requirements: r, Limits: l, Delegation: delegation(depth, children), MinAttestationLevel: attestation(minAtt),
				})
			}
		}),
		"grant revoke": rpc("grant revoke ID --reason TEXT", 1, func(fs *flag.FlagSet) call {
			reason := fs.String("reason", "", "why (recorded)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.grants.RevokeGrant(ctx, &pantherclawv1.RevokeGrantRequest{Id: a[0], Reason: *reason})
			}
		}),
		"grant get": rpc("grant get ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.grants.GetGrant(ctx, &pantherclawv1.GetGrantRequest{Id: a[0]})
			}
		}),
		"grant list": rpc("grant list [--agent ID] [--parent ID] [--state active|revoked]", 0, func(fs *flag.FlagSet) call {
			agent, parent, state := fs.String("agent", "", "only this agent"), fs.String("parent", "", "only grants delegated from this one"),
				fs.String("state", "", "active or revoked")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				st, ok := grantStates[*state]
				if *state != "" && !ok {
					return nil, fmt.Errorf("--state must be active or revoked")
				}
				return c.grants.ListGrants(ctx, &pantherclawv1.ListGrantsRequest{
					PageSize: size(n), PageToken: *tok, AgentId: optStr(*agent), ParentGrantId: optStr(*parent), State: st,
				})
			}
		}),
		"grant budget": rpc("grant budget ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.grants.GetBudgetState(ctx, &pantherclawv1.GetBudgetStateRequest{GrantId: a[0]})
			}
		}),

		"guardrail create": rpc("guardrail create --scope org|bu:ID|team:ID|env:ID|user:ID|service_account:ID --name NAME --bounds-file FILE "+
			"[--requirements-file FILE] [--limits-file FILE] [--max-depth N] [--max-children N] [--max-root-lifetime 168h] "+
			"[--repeat-window 24h] [--min-attestation 0-2]", 0, func(fs *flag.FlagSet) call {
			scope, name := fs.String("scope", "", "where it applies"), fs.String("name", "", "a name")
			docs := termFlags(fs)
			set := settingsFlags(fs)
			minAtt := fs.Int("min-attestation", 0, "lowest workload attestation level under it")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				sc, err := scopeOf(*scope)
				if err != nil {
					return nil, err
				}
				b, r, l, err := docs.read()
				if err != nil {
					return nil, err
				}
				s, err := set.settings()
				if err != nil {
					return nil, err
				}
				return c.guardrails.CreateEnvelope(ctx, &pantherclawv1.CreateEnvelopeRequest{
					Scope: sc, Name: *name, Bounds: b, Requirements: r, Limits: l, Settings: s, MinAttestationLevel: attestation(minAtt),
				})
			}
		}),
		"guardrail revise": rpc("guardrail revise ID --revision N --name NAME --bounds-file FILE [--requirements-file FILE] [--limits-file FILE] "+
			"[--max-depth N] [--max-children N] [--max-root-lifetime 168h] [--repeat-window 24h] [--min-attestation 0-2]", 1, func(fs *flag.FlagSet) call {
			rev, name := fs.Int("revision", 0, "the revision the change is based on"), fs.String("name", "", "a name")
			docs := termFlags(fs)
			set := settingsFlags(fs)
			minAtt := fs.Int("min-attestation", 0, "lowest workload attestation level under it")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				if *rev < 1 {
					return nil, fmt.Errorf("--revision is required (from guardrail get)")
				}
				b, r, l, err := docs.read()
				if err != nil {
					return nil, err
				}
				s, err := set.settings()
				if err != nil {
					return nil, err
				}
				return c.guardrails.ReviseEnvelope(ctx, &pantherclawv1.ReviseEnvelopeRequest{
					Id: a[0], Revision: int32(min(*rev, 1<<30)), Name: *name, Bounds: b, Requirements: r, Limits: l,
					Settings: s, MinAttestationLevel: attestation(minAtt),
				})
			}
		}),
		"guardrail get": rpc("guardrail get ID [--revision N]", 1, func(fs *flag.FlagSet) call {
			rev := fs.Int("revision", 0, "an earlier revision (default: the current one)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				req := &pantherclawv1.GetEnvelopeRequest{Id: a[0]}
				if *rev > 0 {
					req.Revision = proto.Int32(int32(min(*rev, 1<<30)))
				}
				return c.guardrails.GetEnvelope(ctx, req)
			}
		}),
		"guardrail list": rpc("guardrail list [--kind org|bu|team|env|principal]", 0, func(fs *flag.FlagSet) call {
			kind := fs.String("kind", "", "only this scope kind")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				k, ok := scopeKinds[*kind]
				if *kind != "" && !ok {
					return nil, fmt.Errorf("--kind must be org, bu, team, env or principal")
				}
				return c.guardrails.ListEnvelopes(ctx, &pantherclawv1.ListEnvelopesRequest{PageSize: size(n), PageToken: *tok, Kind: k})
			}
		}),

		"fact-provider register": rpc("fact-provider register --name NAME (--sa ID | --gateway ID --connection ID) --fact NAME:TYPE:SUBJECT_TYPE:MAX_LAG ...", 0, func(fs *flag.FlagSet) call {
			name, sa := fs.String("name", "", "provider name"), fs.String("sa", "", "the service account that reports its facts")
			gw := fs.String("gateway", "", "the gateway that reads the connection's system of record and reports its facts (G0 M8)")
			conn := fs.String("connection", "", "with --gateway: the connection")
			var facts list
			fs.Var(&facts, "fact", "a fact it reports, for example payments.charge.refundable:boolean:payments.charge:5m (repeatable)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				req := &pantherclawv1.RegisterProviderRequest{Name: *name, ServiceAccountId: *sa, GatewayId: *gw, ConnectionId: *conn}
				for _, f := range facts {
					d, err := declarationOf(f)
					if err != nil {
						return nil, err
					}
					req.Facts = append(req.Facts, d)
				}
				return c.facts.RegisterProvider(ctx, req)
			}
		}),
		"fact-provider disable": rpc("fact-provider disable ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.facts.DisableProvider(ctx, &pantherclawv1.DisableProviderRequest{Id: a[0]})
			}
		}),
		"fact-provider list": rpc("fact-provider list [--include-disabled]", 0, func(fs *flag.FlagSet) call {
			all := fs.Bool("include-disabled", false, "also disabled providers")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.facts.ListProviders(ctx, &pantherclawv1.ListProvidersRequest{IncludeDisabled: *all})
			}
		}),
		"fact put": rpc("fact put --name NAME --subject-type TYPE --subject-id ID --value-file FILE [--observed TIME]", 0, func(fs *flag.FlagSet) call {
			name, st, sid := fs.String("name", "", "fact name"), fs.String("subject-type", "", "subject type"), fs.String("subject-id", "", "subject id")
			value, observed := fs.String("value-file", "", `typed value (JSON, for example {"bool": true})`), fs.String("observed", "", "when it was observed (default: now)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				v, err := readDocument("value-file", *value)
				if err != nil {
					return nil, err
				}
				if len(v) == 0 {
					return nil, fmt.Errorf("--value-file is required")
				}
				at, err := timeOf("observed", *observed)
				if err != nil {
					return nil, err
				}
				if at == nil {
					at = timestamppb.Now()
				}
				return c.facts.PutFacts(ctx, &pantherclawv1.PutFactsRequest{Observations: []*pantherclawv1.FactObservation{{
					Name: *name, SubjectType: *st, SubjectId: *sid, Value: []byte(strings.TrimSpace(string(v))), ObserveTime: at,
				}}})
			}
		}),
		"fact list": rpc("fact list --subject-type TYPE --subject-id ID [--name NAME ...]", 0, func(fs *flag.FlagSet) call {
			st, sid := fs.String("subject-type", "", "subject type"), fs.String("subject-id", "", "subject id")
			var names list
			fs.Var(&names, "name", "only this fact (repeatable)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.facts.ListFacts(ctx, &pantherclawv1.ListFactsRequest{SubjectType: *st, SubjectId: *sid, Names: names})
			}
		}),

		"package import": rpc("package import --name NAME --version X.Y.Z --targets-file FILE --file FILE", 0, func(fs *flag.FlagSet) call {
			name, version := fs.String("name", "", "package name, for example pc.mock-payments"), fs.String("version", "", "package version")
			targets, file := fs.String("targets-file", "", "the signed targets document that lists it"), fs.String("file", "", "the package file")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				t, err := readDocument("targets-file", *targets)
				if err != nil {
					return nil, err
				}
				p, err := readDocument("file", *file)
				if err != nil {
					return nil, err
				}
				if len(t) == 0 || len(p) == 0 {
					return nil, fmt.Errorf("--targets-file and --file are required")
				}
				return c.packages.ImportPackage(ctx, &pantherclawv1.ImportPackageRequest{
					Name: *name, Version: *version, Targets: strings.TrimSpace(string(t)), Package: p,
				})
			}
		}),
		"package transition": rpc("package transition NAME VERSION --to active|quarantined|retired|reviewed|stale|draft", 2, func(fs *flag.FlagSet) call {
			to := fs.String("to", "", "the new state (activating is human only)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				st, ok := packageStates[*to]
				if !ok {
					return nil, fmt.Errorf("--to must be active, quarantined, retired, reviewed, stale or draft")
				}
				return c.packages.TransitionPackage(ctx, &pantherclawv1.TransitionPackageRequest{Name: a[0], Version: a[1], State: st})
			}
		}),
		"package list": rpc("package list [--name NAME]", 0, func(fs *flag.FlagSet) call {
			name := fs.String("name", "", "only this package")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.packages.ListPackages(ctx, &pantherclawv1.ListPackagesRequest{Name: *name})
			}
		}),
		"package definition": rpc("package definition sha256:DIGEST", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.packages.GetDefinition(ctx, &pantherclawv1.GetDefinitionRequest{Digest: a[0]})
			}
		}),

		"policy create": rpc("policy create --file BUNDLE.json", 0, func(fs *flag.FlagSet) call {
			file := fs.String("file", "", "policy bundle v1 (JSON: id and rules)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				b, err := readDocument("file", *file)
				if err != nil {
					return nil, err
				}
				if len(b) == 0 {
					return nil, fmt.Errorf("--file is required")
				}
				return c.policies.CreatePolicyVersion(ctx, &pantherclawv1.CreatePolicyVersionRequest{Bundle: b})
			}
		}),
		"policy publish": rpcThen("policy publish VERSION_ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.policies.PublishPolicyVersion(ctx, &pantherclawv1.PublishPolicyVersionRequest{Id: a[0]})
			}
		}, changeNote),
		"policy published": rpc("policy published", 0, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.policies.GetPublishedPolicy(ctx, &pantherclawv1.GetPublishedPolicyRequest{})
			}
		}),
		"policy get": rpc("policy get VERSION_ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.policies.GetPolicyVersion(ctx, &pantherclawv1.GetPolicyVersionRequest{Id: a[0]})
			}
		}),
		"policy list": rpc("policy list [--page-size N]", 0, func(fs *flag.FlagSet) call {
			n := fs.Int("page-size", 0, "most versions to list (default 50, at most 200)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.policies.ListPolicyVersions(ctx, &pantherclawv1.ListPolicyVersionsRequest{PageSize: size(n)})
			}
		}),
	}
}

// guardrailSettings are the cap flags of a guardrail; unset flags leave a
// cap as the defaults.
type guardrailSettings struct {
	depth, children     *int
	lifetime, repeatWin *string
}

func settingsFlags(fs *flag.FlagSet) guardrailSettings {
	return guardrailSettings{
		depth:     fs.Int("max-depth", -1, "delegation depth cap (0-4)"),
		children:  fs.Int("max-children", -1, "active children cap per grant (0-50)"),
		lifetime:  fs.String("max-root-lifetime", "", "longest life of a grant a person issues, for example 168h"),
		repeatWin: fs.String("repeat-window", "", "how long a completed irreversible action blocks an identical one (org guardrail only), for example 24h"),
	}
}

func (s guardrailSettings) settings() (*pantherclawv1.GuardrailSettings, error) {
	out := &pantherclawv1.GuardrailSettings{}
	if *s.depth >= 0 {
		out.MaxDepth = proto.Int32(int32(min(*s.depth, 4)))
	}
	if *s.children >= 0 {
		out.MaxChildren = proto.Int32(int32(min(*s.children, 50)))
	}
	for _, d := range []struct {
		flag, v string
		dst     **durationpb.Duration
	}{{"max-root-lifetime", *s.lifetime, &out.MaxRootLifetime}, {"repeat-window", *s.repeatWin, &out.RepeatWindow}} {
		if d.v == "" {
			continue
		}
		v, err := time.ParseDuration(d.v)
		if err != nil {
			return nil, fmt.Errorf("--%s must be a duration such as 24h", d.flag)
		}
		*d.dst = durationpb.New(v)
	}
	return out, nil
}

// declarationOf parses NAME:TYPE:SUBJECT_TYPE:MAX_LAG.
func declarationOf(s string) (*pantherclawv1.FactDeclaration, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 4 {
		return nil, fmt.Errorf("--fact must be NAME:TYPE:SUBJECT_TYPE:MAX_LAG, for example payments.charge.refundable:boolean:payments.charge:5m")
	}
	t, ok := factTypes[parts[1]]
	if !ok {
		return nil, fmt.Errorf("--fact type must be boolean, integer, decimal, money, identifier or timestamp")
	}
	lag, err := time.ParseDuration(parts[3])
	if err != nil {
		return nil, fmt.Errorf("--fact maximum lag must be a duration such as 5m")
	}
	return &pantherclawv1.FactDeclaration{Name: parts[0], Type: t, SubjectType: parts[2], MaxLag: durationpb.New(lag)}, nil
}
