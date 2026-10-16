// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw automation (G0 M11 part 2 D5, D7, D28): create automations, author
// and validate their versions, ask for enabling (people confirm it with a
// security key on the change page), narrow, pause, resume, retire and
// revoke authority; pclaw change lists and declines change requests.
// Every change is made by a person.

type automationClients struct {
	automations pantherclawv1connect.AutomationServiceClient
	changes     pantherclawv1connect.ChangeServiceClient
}

type automationCall func(ctx context.Context, c automationClients, args []string) (proto.Message, error)

type automationVerb struct {
	usage string
	nargs int
	setup func(fs *flag.FlagSet) automationCall
}

// maxDefinitionFile bounds a definition file (the server refuses more).
const maxDefinitionFile = 256 << 10

func readDefinitionFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("--file is required")
	}
	b, err := os.ReadFile(path) //nolint:gosec // a file the person names
	if err != nil {
		return "", err
	}
	if len(b) == 0 || len(b) > maxDefinitionFile {
		return "", fmt.Errorf("%s: a definition is 1 byte to 256 KiB", path)
	}
	return string(b), nil
}

var automationKinds = map[string]pantherclawv1.AutomationKind{
	"agent":    pantherclawv1.AutomationKind_AUTOMATION_KIND_AGENT_WORK,
	"security": pantherclawv1.AutomationKind_AUTOMATION_KIND_SECURITY_WORK,
}

var automationRollouts = map[string]pantherclawv1.AutomationRollout{
	"shadow": pantherclawv1.AutomationRollout_AUTOMATION_ROLLOUT_SHADOW,
	"cohort": pantherclawv1.AutomationRollout_AUTOMATION_ROLLOUT_COHORT,
	"full":   pantherclawv1.AutomationRollout_AUTOMATION_ROLLOUT_FULL,
}

func rolloutFlag(v string) (pantherclawv1.AutomationRollout, error) {
	r, ok := automationRollouts[strings.ToLower(v)]
	if !ok {
		return 0, errors.New("--rollout is shadow, cohort or full")
	}
	return r, nil
}

var automationVerbs = map[string]automationVerb{
	"create": {"create NAME --purpose TEXT --kind agent|security --owner USER_ID", 1, func(fs *flag.FlagSet) automationCall {
		purpose, kind, owner := fs.String("purpose", "", "what it is for (required)"), fs.String("kind", "agent", "agent or security"),
			fs.String("owner", "", "the accountable person (required)")
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			k, ok := automationKinds[*kind]
			if !ok || *purpose == "" || *owner == "" {
				return nil, errors.New("--purpose, --owner and --kind agent|security are required")
			}
			return c.automations.CreateAutomation(ctx, &pantherclawv1.CreateAutomationRequest{Name: a[0], Purpose: *purpose, Kind: k, OwnerUserId: *owner})
		}
	}},
	"get": {"get AUTOMATION_ID", 1, func(*flag.FlagSet) automationCall {
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			return c.automations.GetAutomation(ctx, &pantherclawv1.GetAutomationRequest{Id: a[0]})
		}
	}},
	"list": {"list [--page-size N] [--page-token T]", 0, func(fs *flag.FlagSet) automationCall {
		n, tok := paging(fs)
		return func(ctx context.Context, c automationClients, _ []string) (proto.Message, error) {
			return c.automations.ListAutomations(ctx, &pantherclawv1.ListAutomationsRequest{PageSize: size(n), PageToken: *tok})
		}
	}},
	"draft": {"draft AUTOMATION_ID --file DEFINITION.yaml", 1, func(fs *flag.FlagSet) automationCall {
		file := fs.String("file", "", "the definition, YAML or JSON (required)")
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			def, err := readDefinitionFile(*file)
			if err != nil {
				return nil, err
			}
			return c.automations.CreateDraftVersion(ctx, &pantherclawv1.CreateDraftVersionRequest{AutomationId: a[0], Definition: def})
		}
	}},
	"update": {"update VERSION_ID --file DEFINITION.yaml --base-digest HEX", 1, func(fs *flag.FlagSet) automationCall {
		file, base := fs.String("file", "", "the definition (required)"), fs.String("base-digest", "", "the digest you edited (required)")
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			def, err := readDefinitionFile(*file)
			if err != nil {
				return nil, err
			}
			d, err := hex.DecodeString(*base)
			if err != nil || len(d) != 32 {
				return nil, errors.New("--base-digest is the version's 64-character hex digest")
			}
			return c.automations.UpdateDraftVersion(ctx, &pantherclawv1.UpdateDraftVersionRequest{VersionId: a[0], Definition: def, BaseDigest: d})
		}
	}},
	"validate": {"validate VERSION_ID", 1, func(*flag.FlagSet) automationCall {
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			return c.automations.ValidateVersion(ctx, &pantherclawv1.ValidateVersionRequest{VersionId: a[0]})
		}
	}},
	"version": {"version VERSION_ID", 1, func(*flag.FlagSet) automationCall {
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			return c.automations.GetVersion(ctx, &pantherclawv1.GetVersionRequest{VersionId: a[0]})
		}
	}},
	"versions": {"versions AUTOMATION_ID [--page-size N] [--page-token T]", 1, func(fs *flag.FlagSet) automationCall {
		n, tok := paging(fs)
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			return c.automations.ListVersions(ctx, &pantherclawv1.ListVersionsRequest{AutomationId: a[0], PageSize: size(n), PageToken: *tok})
		}
	}},
	"graph": {"graph VERSION_ID", 1, func(*flag.FlagSet) automationCall {
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			return c.automations.GetVersionGraph(ctx, &pantherclawv1.GetVersionGraphRequest{VersionId: a[0]})
		}
	}},
	"enable": {"enable VERSION_ID --rollout shadow|cohort|full [--agent ID]...", 1, func(fs *flag.FlagSet) automationCall {
		rollout := fs.String("rollout", "shadow", "shadow, cohort or full")
		var agents list
		fs.Var(&agents, "agent", "a cohort agent (cohort rollout; repeatable)")
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			r, err := rolloutFlag(*rollout)
			if err != nil {
				return nil, err
			}
			return c.automations.RequestEnable(ctx, &pantherclawv1.RequestEnableRequest{VersionId: a[0], Rollout: r, CohortAgents: agents})
		}
	}},
	"narrow": {"narrow AUTOMATION_ID --rollout shadow|cohort [--agent ID]...", 1, func(fs *flag.FlagSet) automationCall {
		rollout := fs.String("rollout", "shadow", "shadow or cohort")
		var agents list
		fs.Var(&agents, "agent", "a cohort agent (repeatable)")
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			r, err := rolloutFlag(*rollout)
			if err != nil {
				return nil, err
			}
			return c.automations.NarrowRollout(ctx, &pantherclawv1.NarrowRolloutRequest{AutomationId: a[0], Rollout: r, CohortAgents: agents})
		}
	}},
	"pause": {"pause AUTOMATION_ID [--cancel-active] [--reason TEXT]", 1, func(fs *flag.FlagSet) automationCall {
		cancel, reason := fs.Bool("cancel-active", false, "also cancel active executions"), fs.String("reason", "", "why")
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			return c.automations.PauseAutomation(ctx, &pantherclawv1.PauseAutomationRequest{AutomationId: a[0], CancelActive: *cancel, Reason: *reason})
		}
	}},
	"resume": {"resume AUTOMATION_ID", 1, func(*flag.FlagSet) automationCall {
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			return c.automations.ResumeAutomation(ctx, &pantherclawv1.ResumeAutomationRequest{AutomationId: a[0]})
		}
	}},
	"retire": {"retire AUTOMATION_ID [--reason TEXT]", 1, func(fs *flag.FlagSet) automationCall {
		reason := fs.String("reason", "", "why")
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			return c.automations.RetireAutomation(ctx, &pantherclawv1.RetireAutomationRequest{AutomationId: a[0], Reason: *reason})
		}
	}},
	"set-owner": {"set-owner AUTOMATION_ID USER_ID", 2, func(*flag.FlagSet) automationCall {
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			return c.automations.SetAutomationOwner(ctx, &pantherclawv1.SetAutomationOwnerRequest{AutomationId: a[0], OwnerUserId: a[1]})
		}
	}},
	"revoke-authority": {"revoke-authority AUTOMATION_ID --reason TEXT", 1, func(fs *flag.FlagSet) automationCall {
		reason := fs.String("reason", "", "why (required)")
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			if strings.TrimSpace(*reason) == "" {
				return nil, errors.New("--reason is required")
			}
			return c.automations.RevokeAuthority(ctx, &pantherclawv1.RevokeAuthorityRequest{AutomationId: a[0], Reason: *reason})
		}
	}},
}

var changeVerbs = map[string]automationVerb{
	"get": {"get CHANGE_ID", 1, func(*flag.FlagSet) automationCall {
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			return c.changes.GetChangeRequest(ctx, &pantherclawv1.GetChangeRequestRequest{Id: a[0]})
		}
	}},
	"list": {"list [--domain automation|protected|publisher] [--subject ID] [--page-size N] [--page-token T]", 0, func(fs *flag.FlagSet) automationCall {
		domain, subject := fs.String("domain", "", "only this domain"), fs.String("subject", "", "only about this subject")
		n, tok := paging(fs)
		return func(ctx context.Context, c automationClients, _ []string) (proto.Message, error) {
			return c.changes.ListChangeRequests(ctx, &pantherclawv1.ListChangeRequestsRequest{
				Domain: *domain, SubjectId: optString(*subject), PageSize: size(n), PageToken: *tok,
			})
		}
	}},
	"decline": {"decline CHANGE_ID --reason TEXT", 1, func(fs *flag.FlagSet) automationCall {
		reason := fs.String("reason", "", "why (required)")
		return func(ctx context.Context, c automationClients, a []string) (proto.Message, error) {
			if strings.TrimSpace(*reason) == "" {
				return nil, errors.New("--reason is required")
			}
			return c.changes.DeclineChangeRequest(ctx, &pantherclawv1.DeclineChangeRequestRequest{Id: a[0], Reason: *reason})
		}
	}},
}

func verbUsage(prefix string, verbs map[string]automationVerb) string {
	names := make([]string, 0, len(verbs))
	for k := range verbs {
		names = append(names, k)
	}
	slices.Sort(names)
	lines := make([]string, 0, len(names))
	for _, v := range names {
		lines = append(lines, prefix+" "+verbs[v].usage)
	}
	return strings.Join(lines, "\n  pclaw ")
}

func init() {
	commands["automation"] = command{usage: verbUsage("automation", automationVerbs), run: runVerbs("automation", automationVerbs)}
	commands["change"] = command{usage: verbUsage("change", changeVerbs), run: runVerbs("change", changeVerbs)}
}

func runVerbs(prefix string, verbs map[string]automationVerb) func(ctx context.Context, a *app, args []string) error {
	return func(ctx context.Context, a *app, args []string) error {
		if len(args) == 0 {
			return errUsage
		}
		v, ok := verbs[args[0]]
		if !ok || len(args)-1 < v.nargs {
			return errUsage
		}
		args = args[1:]
		fs := flag.NewFlagSet(prefix+" "+v.usage, flag.ContinueOnError)
		fs.SetOutput(a.stderr)
		fn := v.setup(fs)
		if err := fs.Parse(args[v.nargs:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errUsage
		}
		s, err := a.session()
		if err != nil {
			return err
		}
		conn := s.connect()
		res, err := fn(ctx, automationClients{
			automations: pantherclawv1connect.NewAutomationServiceClient(conn),
			changes:     pantherclawv1connect.NewChangeServiceClient(conn),
		}, args[:v.nargs])
		if err != nil {
			return err
		}
		if r, ok := res.(*pantherclawv1.RequestEnableResponse); ok {
			_, _ = fmt.Fprintf(a.stderr, "Waiting for confirmation by %d person(s) with a security key at /changes/%s\n", r.GetRequired(), r.GetChangeRequestId())
		}
		return a.print(res)
	}
}
