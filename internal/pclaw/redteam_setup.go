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
	var notes []string
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
	provs, err := c.facts.ListProviders(ctx, &pantherclawv1.ListProvidersRequest{})
	if err != nil {
		return fmt.Errorf("listing fact providers: %w", err)
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
		twinID := ""
		if have, ok := byName[twin]; ok {
			if !have.GetSimulated() || have.GetBaseUrl() != base {
				return fmt.Errorf("connection %s exists and is not the simulated twin of %s at %s; nothing was changed", twin, orig.GetName(), base)
			}
			twinID = have.GetId()
		} else {
			steps = append(steps, setupStep{
				text: fmt.Sprintf("create the simulated connection %q, a twin of %q, pointing at %s", twin, orig.GetName(), base),
				apply: func(ctx context.Context) error {
					res, err := c.connections.CreateConnection(ctx, &pantherclawv1.CreateConnectionRequest{
						Name: twin, Kind: orig.GetKind(), GatewayId: orig.GetGatewayId(), Package: orig.GetPackage(), BaseUrl: base,
						AccessMode: orig.GetAccessMode(), CredentialHeader: orig.GetCredentialHeader(), CredentialScheme: orig.GetCredentialScheme(),
						DestinationClass: orig.GetDestinationClass(), DefaultMode: orig.GetDefaultMode(),
						MaxResponseBytes: orig.GetMaxResponseBytes(), TimeoutMs: orig.GetTimeoutMs(), Simulated: true,
					})
					twinID = res.GetConnection().GetId()
					return err
				},
			})
		}
		step, note := twinProviderStep(c, provs, orig, twin, &twinID)
		if step != nil {
			steps = append(steps, *step)
		}
		if note != "" {
			notes = append(notes, note)
		}
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
			deleg := rangeDelegation(g.GetDelegation())
			steps = append(steps, setupStep{
				text: fmt.Sprintf("issue the range agent a grant like %s (same bounds, requirements and limits; delegation depth %d), lasting %s",
					g.GetId(), deleg.GetDepth(), *expires),
				apply: func(ctx context.Context) error {
					_, err := c.grants.IssueGrant(ctx, &pantherclawv1.IssueGrantRequest{
						AgentId: agentID, Principal: g.GetPrincipal(), TaskRef: "adversarial range",
						ExpireTime: timestamppb.New(time.Now().Add(*expires)),
						Bounds:     g.GetBounds(), Requirements: g.GetRequirements(), Limits: g.GetLimits(),
						Delegation: deleg, MinAttestationLevel: g.GetMinAttestationLevel(),
					})
					if err != nil {
						// An envelope that caps delegation lower refuses the grant: the server names it.
						return fmt.Errorf("the range grant needs delegation depth %d (agent.child scenarios delegate from their run) and was refused; if a guardrail envelope caps delegation lower, widen it or drop those scenarios: %w",
							deleg.GetDepth(), err)
					}
					return nil
				},
			})
		}
	}

	w := a.stdout
	defer func() {
		for _, n := range notes {
			_, _ = fmt.Fprintf(w, "Note: %s\n", n)
		}
	}()
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
		"  pclaw redteam run --scenarios redteam/scenarios --workload-file FILE --gateway URL --role github=<twin>\n"+
		"    --fixture owner=<owner> --fixture repo=<repo> --fixture other_repo=<repo> --fixture main=<sha> --fixture file_b64=<base64>\n\n"+
		"The fixtures owner, repo, other_repo, main and file_b64 describe the GitHub simulator and are yours to supply; each scenario opens its own\n"+
		"pull requests, and the nonce and the planted key and token are made fresh for every run.\n")
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

// minRangeDepth is the depth a range grant needs: scenarios start their own
// runs on the root grant, and agent.child scenarios delegate from them.
const minRangeDepth = 2

// maxGrantDepth is the deepest a grant may delegate.
const maxGrantDepth = 4

// rangeDelegation is the like-grant's delegation made one level deeper (at
// least two) so that agent.child works. Fan-out stays as the real grant has
// it: scenarios run in runs of their own, not in delegated children.
func rangeDelegation(like *pantherclawv1.GrantDelegation) *pantherclawv1.GrantDelegation {
	return &pantherclawv1.GrantDelegation{
		Depth:       min(max(like.GetDepth()+1, minRangeDepth), maxGrantDepth),
		MaxChildren: like.GetMaxChildren(),
	}
}

var twinProviderNameRe = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)

// twinProviderStep plans the fact provider of a simulated twin (D43): the
// real connection's gateway provider has facts the twin's actions need
// (github.* and the like), and a fact name has one provider per connection.
// The twin's is named "<real provider>.range" (hyphens become underscores),
// bound to the gateway and the twin, and declares exactly what the real
// one does. It returns a step, or a note when there is nothing to register.
// twinID is the twin's id: known when it exists, set when its step has run.
func twinProviderStep(c clients, provs *pantherclawv1.ListProvidersResponse, orig *pantherclawv1.Connection, twin string, twinID *string) (*setupStep, string) {
	var realProv *pantherclawv1.FactProvider
	taken := map[string]bool{}
	for _, p := range provs.GetProviders() {
		taken[p.GetName()] = true
		if realProv == nil && p.GetConnectionId() == orig.GetId() && p.GetGatewayId() != "" && p.GetState() == pantherclawv1.ProviderState_PROVIDER_STATE_ACTIVE {
			realProv = p
		}
	}
	if realProv == nil {
		return nil, fmt.Sprintf("%s has no gateway fact provider, so its twin %s gets none: scenarios that read facts there will see none", orig.GetName(), twin)
	}
	name := strings.ReplaceAll(realProv.GetName(), "-", "_") + ".range"
	if !twinProviderNameRe.MatchString(name) {
		return nil, fmt.Sprintf("the twin of fact provider %q cannot be named %q, so %s gets no facts", realProv.GetName(), name, twin)
	}
	if taken[name] {
		return nil, fmt.Sprintf("fact provider %s already exists (the twin of %s)", name, realProv.GetName())
	}
	return &setupStep{
		text: fmt.Sprintf("register the fact provider %q for %q, declaring the same %d facts as %q", name, twin, len(realProv.GetFacts()), realProv.GetName()),
		apply: func(ctx context.Context) error {
			if *twinID == "" {
				return errors.New("the twin connection has no id yet")
			}
			_, err := c.facts.RegisterProvider(ctx, &pantherclawv1.RegisterProviderRequest{
				Name: name, Facts: realProv.GetFacts(), GatewayId: orig.GetGatewayId(), ConnectionId: *twinID,
			})
			return err
		},
	}, ""
}
