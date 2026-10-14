// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"regexp"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// pclaw redteam setup (G0 M12, D14): as a person, through the server's APIs
// only (so each step is authorized and audited there as if made by hand), it
// prepares a range: a range agent, simulated twins of chosen real
// connections that point at simulator addresses, and a grant for the range
// agent shaped like a chosen real grant. The plan comes first; --dry-run
// changes nothing. What already exists is left as it is; what exists and
// differs stops the setup before anything is changed.

func init() {
	commands["redteam setup"] = command{
		usage: "redteam setup --name NAME --team ID --env ID --owner USER --context desktop|ci|kubernetes|service " +
			"--twin PACKAGE=BASE_URL… [--like-grant ID] [--expires DURATION] [--dry-run] [--yes]",
		run: redteamSetup,
	}
}

var twinRe = regexp.MustCompile(`^([a-z0-9][a-z0-9.-]{0,127})=(.+)$`)

// setupStep is one planned change.
type setupStep struct {
	text  string
	apply func(ctx context.Context) error
}

func redteamSetup(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("redteam setup", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	name := fs.String("name", "", "the range agent's name")
	team, env, owner := fs.String("team", "", "team id"), fs.String("env", "", "environment id"), fs.String("owner", "", "owner user id")
	ctxName := fs.String("context", "", "where the range instance runs (fixed for its life)")
	var twins list
	fs.Var(&twins, "twin", "make a simulated twin of the first active real connection of PACKAGE, pointing at BASE_URL (repeatable)")
	likeGrant := fs.String("like-grant", "", "issue the range agent a grant shaped like this real grant")
	expires := fs.Duration("expires", 7*24*time.Hour, "how long the range agent's grant lasts")
	dryRun, yes := fs.Bool("dry-run", false, "show the plan and change nothing"), fs.Bool("yes", false, "apply without asking")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *name == "" || *team == "" || *env == "" || *owner == "" || *ctxName == "" || len(twins) == 0 {
		return errUsage
	}
	for _, id := range []string{*team, *env, *owner} {
		if !uuidRe.MatchString(id) {
			return fmt.Errorf("%q is not an id", id)
		}
	}
	if *likeGrant != "" && !uuidRe.MatchString(*likeGrant) {
		return fmt.Errorf("--like-grant: %q is not an id", *likeGrant)
	}
	if *expires <= 0 {
		return errors.New("--expires must be positive")
	}
	ec, err := execContext(*ctxName)
	if err != nil {
		return err
	}
	c, err := a.clients()
	if err != nil {
		return err
	}

	var steps []setupStep
	agentID := ""

	// The range agent: reused when one of that name exists.
	agents, err := allAgents(ctx, c)
	if err != nil {
		return err
	}
	for _, ag := range agents {
		if ag.GetName() != *name {
			continue
		}
		if !ag.GetRangeAgent() {
			return fmt.Errorf("an agent named %q exists and is not a range agent; nothing was changed (pick another --name)", *name)
		}
		agentID = ag.GetId()
	}
	if agentID == "" {
		steps = append(steps, setupStep{
			text: fmt.Sprintf("create the range agent %q (every run of it is simulated; at most 5 per org)", *name),
			apply: func(ctx context.Context) error {
				res, err := c.agents.CreateAgent(ctx, &pantherclawv1.CreateAgentRequest{
					Name: *name, Purpose: "Adversarial range: tests PantherClaw's controls against simulated targets",
					TeamId: *team, EnvironmentId: *env, OwnerUserId: *owner, ExecutionContext: ec, RangeAgent: true,
				})
				if err != nil {
					return err
				}
				agentID = res.GetAgent().GetId()
				return nil
			},
		})
	}

	// The simulated twins.
	conns, err := allConnections(ctx, c)
	if err != nil {
		return err
	}
	byName := map[string]*pantherclawv1.Connection{}
	for _, cn := range conns {
		byName[cn.GetName()] = cn
	}
	for _, t := range twins {
		m := twinRe.FindStringSubmatch(t)
		if m == nil || len(m[2]) > 2048 {
			return fmt.Errorf("--twin %q must be PACKAGE=BASE_URL", t)
		}
		pkg, base := m[1], m[2]
		var orig *pantherclawv1.Connection
		for _, cn := range conns {
			if cn.GetPackage() == pkg && !cn.GetSimulated() && cn.GetState() == pantherclawv1.ConnectionState_CONNECTION_STATE_ACTIVE {
				orig = cn
				break
			}
		}
		if orig == nil {
			return fmt.Errorf("--twin %s: no active real connection of that package to copy; create one first", pkg)
		}
		twin := strings.TrimSuffix(orig.GetName(), "-range")
		if len(twin) > 57 {
			twin = twin[:57]
		}
		twin += "-range"
		if have, ok := byName[twin]; ok {
			if !have.GetSimulated() || have.GetBaseUrl() != base {
				return fmt.Errorf("connection %s exists and is not the simulated twin of %s at %s; nothing was changed", twin, orig.GetName(), base)
			}
			continue
		}
		steps = append(steps, setupStep{
			text: fmt.Sprintf("create the simulated connection %q, a twin of %q, pointing at %s", twin, orig.GetName(), base),
			apply: func(ctx context.Context) error {
				_, err := c.connections.CreateConnection(ctx, &pantherclawv1.CreateConnectionRequest{
					Name: twin, Kind: orig.GetKind(), GatewayId: orig.GetGatewayId(), Package: orig.GetPackage(), BaseUrl: base,
					AccessMode: orig.GetAccessMode(), CredentialHeader: orig.GetCredentialHeader(), CredentialScheme: orig.GetCredentialScheme(),
					DestinationClass: orig.GetDestinationClass(), DefaultMode: orig.GetDefaultMode(),
					MaxResponseBytes: orig.GetMaxResponseBytes(), TimeoutMs: orig.GetTimeoutMs(), Simulated: true,
				})
				return err
			},
		})
	}

	// The grant, shaped like a real one.
	if *likeGrant != "" {
		like, err := c.grants.GetGrant(ctx, &pantherclawv1.GetGrantRequest{Id: *likeGrant})
		if err != nil {
			return err
		}
		have := false
		if agentID != "" {
			gs, err := c.grants.ListGrants(ctx, &pantherclawv1.ListGrantsRequest{
				PageSize: 200, AgentId: &agentID, State: pantherclawv1.GrantState_GRANT_STATE_ACTIVE,
			})
			if err != nil {
				return err
			}
			have = len(gs.GetGrants()) > 0
		}
		if !have {
			g := like.GetGrant()
			steps = append(steps, setupStep{
				text: fmt.Sprintf("issue the range agent a grant like %s (same bounds, requirements and limits), lasting %s", g.GetId(), *expires),
				apply: func(ctx context.Context) error {
					_, err := c.grants.IssueGrant(ctx, &pantherclawv1.IssueGrantRequest{
						AgentId: agentID, Principal: g.GetPrincipal(), TaskRef: "adversarial range",
						ExpireTime: timestamppb.New(time.Now().Add(*expires)),
						Bounds:     g.GetBounds(), Requirements: g.GetRequirements(), Limits: g.GetLimits(),
						Delegation: g.GetDelegation(), MinAttestationLevel: g.GetMinAttestationLevel(),
					})
					return err
				},
			})
		}
	}

	w := a.stdout
	if len(steps) == 0 {
		_, err := fmt.Fprintln(w, "Nothing to do: the range agent, its twins and its grant are already as asked.")
		return err
	}
	_, _ = fmt.Fprintln(w, "Plan:")
	for i, s := range steps {
		_, _ = fmt.Fprintf(w, "  %d. %s\n", i+1, s.text)
	}
	if *dryRun {
		_, err := fmt.Fprintln(w, "\nDry run: nothing was changed.")
		return err
	}
	if !*yes && !confirm(a, fmt.Sprintf("Make these %d change(s)?", len(steps))) {
		return errors.New("not applied")
	}
	for i, s := range steps {
		if err := s.apply(ctx); err != nil {
			return fmt.Errorf("step %d (%s): %w", i+1, s.text, err)
		}
		_, _ = fmt.Fprintf(w, "done: %s\n", s.text)
	}
	_, err = fmt.Fprintf(w, "\nNext: start the simulators at the twin addresses, enroll a workload for the range agent "+
		"(pclaw workload init, then enroll, then pclaw run start), and run:\n"+
		"  pclaw redteam run --scenarios redteam/scenarios --workload-file FILE --gateway URL --role github=<twin> --fixture pr=<number>\n")
	return err
}

// maxSetupPages bounds paging through an org's agents or connections.
const maxSetupPages = 100

// allAgents pages through every agent of the org.
func allAgents(ctx context.Context, c clients) ([]*pantherclawv1.Agent, error) {
	var out []*pantherclawv1.Agent
	tok := ""
	for range maxSetupPages {
		res, err := c.agents.ListAgents(ctx, &pantherclawv1.ListAgentsRequest{PageSize: 200, PageToken: tok})
		if err != nil {
			return nil, err
		}
		out = append(out, res.GetAgents()...)
		if tok = res.GetNextPageToken(); tok == "" {
			return out, nil
		}
	}
	return nil, errors.New("too many agents to list")
}

// allConnections pages through every connection of the org.
func allConnections(ctx context.Context, c clients) ([]*pantherclawv1.Connection, error) {
	var out []*pantherclawv1.Connection
	tok := ""
	for range maxSetupPages {
		res, err := c.connections.ListConnections(ctx, &pantherclawv1.ListConnectionsRequest{PageSize: 200, PageToken: tok})
		if err != nil {
			return nil, err
		}
		out = append(out, res.GetConnections()...)
		if tok = res.GetNextPageToken(); tok == "" {
			return out, nil
		}
	}
	return nil, errors.New("too many connections to list")
}
