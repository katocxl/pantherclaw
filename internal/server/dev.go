// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
	pcawsecs "github.com/katocxl/pantherclaw/packages/pc-aws-ecs"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
	pcgitlab "github.com/katocxl/pantherclaw/packages/pc-gitlab"
	pcjira "github.com/katocxl/pantherclaw/packages/pc-jira"
	pcshell "github.com/katocxl/pantherclaw/packages/pc-shell"
	pcslack "github.com/katocxl/pantherclaw/packages/pc-slack"
)

// devSeedActor records `dev seed` in the audit log.
var devSeedActor = evdomain.Actor{Type: "operator", ID: "dev-seed"}

// cmdDev implements `dev seed`: a demo org with its containment row and the
// reference payments package imported and active, and optionally an
// enrollment file for a development gateway (it then authenticates with a
// certificate from the internal CA, like any gateway) and a ready-to-use
// workload: an admitted instance, a fact provider for refundable charges, a
// grant and a run bound to both. `dev gateway` writes an enrollment file for
// an existing org. DEVELOPMENT ONLY.
func cmdDev(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	if len(args) > 0 && args[0] == "gateway" {
		return cmdDevGateway(ctx, args[1:], stdout, stderr, env)
	}
	if len(args) > 0 && args[0] == "connection" {
		return cmdDevConnection(ctx, args[1:], stdout, stderr, env)
	}
	if len(args) == 0 || args[0] != "seed" {
		_, _ = fmt.Fprint(stderr, usage)
		return errUsage
	}
	fs := flag.NewFlagSet("dev seed", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "JSON configuration file")
	name := fs.String("org-name", "dev-org", "name of the new org")
	limit := fs.String("budget-limit", "1000.00", "the seeded grant's task budget, in the grant currency")
	maxCount := fs.Int("max-count", 0, "optional limit on the number of refunds the seeded grant allows (0 = none)")
	gatewayOut := fs.String("gateway-out", "", "also seed a gateway; write its enrollment file here (0600, never overwritten)")
	targetURL := fs.String("target-url", "", "with --gateway-out: also seed the connection \"payments\" to this payments API, in enforce mode")
	access := fs.String("access-mode", "", "with --target-url: "+accessUsage+" (default none)")
	shell := fs.Bool("shell", false, "with --gateway-out: also seed the pc.shell package and the hook connection \"shell\" (Claude Code), in enforce mode; "+
		"with --workload-out the grant also allows shell commands")
	githubURL := fs.String("github-url", "", "with --gateway-out: also seed pc.github and the connection \"github\" to this GitHub API "+
		"(pantherclaw-sim github), held by the gateway (seal the GitHub App with pclaw seal --github-app), the gateway as its fact provider, "+
		"and, with --workload-out, the GitHub operations in the grant")
	stripeURL := fs.String("stripe-url", "", "with --gateway-out: also seed pc.stripe and the connection \"stripe\" to this Stripe API (pantherclaw-sim stripe), "+
		"held by the gateway, its facts read by the gateway, refunds over "+devStripeHoldOver+" USD held; seal a restricted test key with pclaw seal")
	stripePayee := fs.String("stripe-payee", devStripePayee, "with --stripe-url and --workload-out: the connected account the seeded grant may transfer to")
	a2aURL := fs.String("a2a-url", "", "with --gateway-out and --workload-out: also seed pc.a2a, the peer agent dev-peer and the simulated a2a connection \"peer\" "+
		"to this A2A agent (pantherclaw-sim a2a), its card pinned, and the a2a operations in the grant (G0 M14 D33)")
	a2aPeerOut := fs.String("a2a-peer-out", "", "with --a2a-url: write the peer agent's key file here (0600, never overwritten)")
	workloadOut := fs.String("workload-out", "", "also seed an admitted PAP/1 workload with a grant and a run; write its key file here (0600, never overwritten)")
	factsOut := fs.String("facts-key-out", "", "with --workload-out: write the API key of the development fact provider here (0600, never overwritten)")
	holdOver := fs.String("hold-over", "50.00", "publish a policy holding refunds over this amount (grant currency) for an approver; empty for none")
	postgresFile := fs.String("postgres", "", "with --gateway-out: also seed pc.postgres and the connection \"warehouse\" to the database a file names as one URL (G0 M14 D21)")
	slackChannel := fs.String("slack-channel", "", "also seed a PENDING slack_app channel posting approval cards to this Slack channel id (with --slack-token-file; Team edition)")
	slackToken := fs.String("slack-token-file", "", "with --slack-channel: the file holding the bot token (xoxb-...)")
	slackURL := fs.String("slack-url", "", "with --gateway-out: also seed pc.slack and the connection \"slack\" to this Slack Web API base (pantherclaw-sim slack: http://127.0.0.1:9095/api), its channel facts read by the gateway")
	jiraURL := fs.String("jira-url", "", "with --gateway-out: also seed pc.jira and the connection \"jira\" to this Jira site (pantherclaw-sim jira: http://127.0.0.1:9096), its project facts read by the gateway")
	awsECSURL := fs.String("aws-ecs-url", "", "with --gateway-out: also seed pc.aws.ecs and the connection \"aws-ecs\" to this ECS endpoint (pantherclaw-sim aws)")
	gitlabURL := fs.String("gitlab-url", "", "with --gateway-out: also seed pc.gitlab and the connection \"gitlab\" to this GitLab instance (pantherclaw-sim gitlab: http://127.0.0.1:9097), its merge request facts read by the gateway")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *maxCount < 0 || (*factsOut != "" && *workloadOut == "") {
		fs.Usage()
		return errUsage
	}
	cfg, _, err := loadConfig([]string{"--config", *cfgPath}, stderr, env, "dev seed")
	if err != nil {
		return err
	}
	// The seed mints keys and credentials for a demo org, so it runs only
	// against a server that is reachable from this machine alone (HR-163),
	// and writes only to a database on this machine: database.host must be
	// loopback or a unix socket directory. A loopback tunnel to a remote
	// database looks local and is out of scope of this check.
	if err := errors.Join(cfg.localOnly(), localDatabase(cfg.DB.Host)); err != nil {
		return fmt.Errorf("dev seed is development-only (HR-163): %w", err)
	}
	lim, err := money.ParseMoney(*limit, cfg.Authority.GrantCurrency)
	if err != nil || lim.Amount.Sign() <= 0 {
		return fmt.Errorf("dev seed: --budget-limit must be a positive %s amount", cfg.Authority.GrantCurrency)
	}
	maxPer, err := money.ParseMoney(cfg.Authority.GrantMaxPerAction, cfg.Authority.GrantCurrency)
	if err != nil {
		return fmt.Errorf("dev seed: authority.grant_max_per_action: %w", err)
	}
	var hold *money.Money
	if *holdOver != "" {
		h, err := money.ParseMoney(*holdOver, cfg.Authority.GrantCurrency)
		if err != nil || h.Amount.Sign() <= 0 {
			return fmt.Errorf("dev seed: --hold-over must be a positive %s amount", cfg.Authority.GrantCurrency)
		}
		hold = &h
	}
	for _, out := range []string{*workloadOut, *factsOut, *gatewayOut} {
		if out == "" {
			continue
		}
		if _, err := os.Stat(out); err == nil {
			return fmt.Errorf("dev seed: %s already exists", out)
		}
	}
	if (*targetURL != "" || *shell || *githubURL != "" || *stripeURL != "" || *postgresFile != "" || *slackURL != "" || *a2aURL != "" ||
		*jiraURL != "" || *gitlabURL != "" || *awsECSURL != "") && *gatewayOut == "" {
		return errTargetNeedsGateway
	}
	if *a2aURL != "" && (*workloadOut == "" || *a2aPeerOut == "") {
		return errors.New("dev seed: --a2a-url needs --workload-out and --a2a-peer-out")
	}
	if *access == "" {
		*access = capp.AccessNone
	} else if *targetURL == "" || !slices.Contains(devAccessModes, *access) {
		return errAccessMode
	}
	if *gatewayOut != "" && cfg.GatewayAPI.Addr == "" {
		return errors.New("dev seed: --gateway-out needs gateway_api in the server config (gateways reach the Authority only over mTLS)")
	}
	signer, err := devPackageSigner(cfg, stdout)
	if err != nil {
		return err
	}
	appCfg, err := cfg.dbConfig(cfg.DB.AppUser, cfg.DB.AppPasswordFile, 2)
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, appCfg)
	if err != nil {
		return err
	}
	defer pool.Close()

	org := ids.New[ids.Org]()
	var w devWorkload
	var kf workloadclient.KeyFile
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, $2)", org, *name); err != nil {
			return fmt.Errorf("dev seed: org: %w", err)
		}
		if err := dbq.New(tx).InsertContainment(ctx, org); err != nil {
			return fmt.Errorf("dev seed: containment: %w", err)
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "dev.org_seeded", Actor: devSeedActor, Outcome: audit.Success,
			Object: &audit.Object{Type: "org", ID: org.String()},
		}); err != nil {
			return err
		}
		if *workloadOut != "" {
			w, kf, err = seedWorkload(ctx, tx, org, cfg.Auth.PublicURL)
		}
		return err
	})
	if err != nil {
		return err
	}
	pkgs := []devPackage{{mockpayments.Name, mockpayments.Version, mockpayments.Package}}
	if *shell {
		pkgs = append(pkgs, devPackage{pcshell.Name, pcshell.Version, pcshell.Package})
	}
	if *githubURL != "" {
		pkgs = append(pkgs, devPackage{pcgithub.Name, pcgithub.Version, pcgithub.Package})
	}
	if *stripeURL != "" {
		pkgs = append(pkgs, devStripePackage())
	}
	if *postgresFile != "" {
		pkgs = append(pkgs, devPostgresPackage())
	}
	if *slackURL != "" {
		pkgs = append(pkgs, devPackage{pcslack.Name, pcslack.Version, pcslack.Package})
	}
	if *a2aURL != "" {
		pkgs = append(pkgs, devA2APackage())
	}
	if *jiraURL != "" {
		pkgs = append(pkgs, devPackage{pcjira.Name, pcjira.Version, pcjira.Package})
	}
	if *gitlabURL != "" {
		pkgs = append(pkgs, devPackage{pcgitlab.Name, pcgitlab.Version, pcgitlab.Package})
	}
	if *awsECSURL != "" {
		pkgs = append(pkgs, devPackage{pcawsecs.Name, pcawsecs.Version, pcawsecs.Package})
	}
	if err := seedPackages(ctx, pool, org, signer, pkgs...); err != nil {
		return err
	}
	if *slackChannel != "" {
		if err := seedSlackChannel(ctx, cfg, pool, org, *slackChannel, *slackToken, stdout); err != nil {
			return err
		}
	}
	_, _ = fmt.Fprintf(stdout, "seeded org %s (%q) with package %s@%s active\n", org, *name, mockpayments.Name, mockpayments.Version)
	if hold != nil {
		if _, err := seedHoldPolicy(ctx, pool, org, *hold, cfg.CEL); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "published policy dev-holds: refunds over %s wait for an approver (%s)\n%s", hold, devHoldReason,
			approverSteps(cfg.Auth.PublicURL, org))
	}
	if *gatewayOut != "" {
		gw, err := seedGateway(ctx, cfg, pool, org, "dev-gateway", *gatewayOut)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "seeded gateway %s; within 15 minutes, start it with: pantherclaw-gateway serve --enroll-file %s\n",
			gw, *gatewayOut)
		if err := seedApproverKeys(ctx, cfg, pool, org, *gatewayOut, stdout); err != nil {
			return err
		}
		if *targetURL != "" {
			c, err := seedConnection(ctx, cfg, pool, org, gw, devConnectionName, *targetURL, "enforce", *access)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "seeded connection %s (%s, access %s) to %s; agents call the gateway at /%s/v1/refunds\n",
				c.ID, c.Name, *access, *targetURL, c.Name)
		}
		if *githubURL != "" {
			c, err := seedGitHubConnection(ctx, cfg, pool, org, gw, *githubURL)
			if err != nil {
				return err
			}
			if err := seedGitHubFacts(ctx, pool, org, gw, c.ID); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "seeded github connection %s (%s) to %s, its facts read by the gateway; seal the GitHub App with "+
				"pclaw seal --connection %s --github-app ID --installation N --account LOGIN --from-file KEY.pem\n", c.ID, c.Name, *githubURL, c.ID)
		}
		if *stripeURL != "" {
			if err := seedStripe(ctx, cfg, pool, org, gw, *stripeURL, hold, stdout); err != nil {
				return err
			}
		}
		if *postgresFile != "" {
			if err := seedPostgresConnection(ctx, cfg, pool, org, gw, *postgresFile, stdout); err != nil {
				return err
			}
		}
		if *slackURL != "" {
			c, err := seedSlackAgentConnection(ctx, cfg, pool, org, gw, *slackURL)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "seeded slack connection %s (%s) to %s, its channel facts read by the gateway; seal the bot token with "+
				"pclaw seal --connection %s --from-file TOKEN\n", c.ID, c.Name, *slackURL, c.ID)
		}
		if *jiraURL != "" {
			c, err := seedJiraAgentConnection(ctx, cfg, pool, org, gw, *jiraURL)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "seeded jira connection %s (%s) to %s, its project facts read by the gateway; seal base64 of email:api-token with "+
				"pclaw seal --connection %s --from-file SECRET\n", c.ID, c.Name, *jiraURL, c.ID)
		}
		if *gitlabURL != "" {
			c, err := seedGitLabAgentConnection(ctx, cfg, pool, org, gw, *gitlabURL)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "seeded gitlab connection %s (%s) to %s, its merge request facts read by the gateway; seal an access token with "+
				"pclaw seal --connection %s --from-file TOKEN\n", c.ID, c.Name, *gitlabURL, c.ID)
		}
		if *awsECSURL != "" {
			c, err := seedAWSECSAgentConnection(ctx, cfg, pool, org, gw, *awsECSURL)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "seeded aws-ecs connection %s (%s) to %s, its deployment controller read by the gateway; seal a base key with "+
				"pclaw seal --connection %s --from-file SECRET --aws-access-key-id ID --aws-role-arn ARN --aws-sts-url URL --aws-sts-region R --aws-region R --aws-service ecs\n",
				c.ID, c.Name, *awsECSURL, c.ID)
		}
		if *a2aURL != "" {
			if err := seedA2A(ctx, cfg, pool, org, gw, w, *a2aURL, *a2aPeerOut, stdout); err != nil {
				return err
			}
		}
		if *shell {
			c, err := seedShellConnection(ctx, cfg, pool, org, gw)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "seeded package %s@%s and connection %s (%s); the Claude Code hook asks the gateway at /hook/%s\n",
				pcshell.Name, pcshell.Version, c.ID, c.Name, c.Name)
		}
	}
	if *workloadOut == "" {
		return nil
	}
	key, err := seedFacts(ctx, pool, org, credential.Env(cfg.Auth.APIKeyEnv))
	if err != nil {
		return err
	}
	g, err := seedGrant(ctx, pool, org, w, devGrantTerms{
		MaxPerAction: maxPer, Limit: lim, MaxCount: *maxCount, Shell: *shell, GitHub: *githubURL != "", Stripe: *stripeURL != "",
		StripePayee: *stripePayee, Postgres: *postgresFile != "", A2A: *a2aURL != "",
	})
	if err != nil {
		return err
	}
	run, err := seedRun(ctx, pool, org, w, g.ID.UUID(), g.ExpiresAt)
	if err != nil {
		return err
	}
	kf.RunID = run.String()
	if err := workloadclient.WriteKeyFile(*workloadOut, kf, false); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "seeded workload %s with grant %s (refunds up to %s, task budget %s) and run %s; key file %s\n",
		kf.Identifier, g.ID, maxPer, lim, kf.RunID, *workloadOut)
	if *factsOut != "" {
		if err := writeSecretFile(*factsOut, key.Reveal()); err != nil {
			return fmt.Errorf("dev seed: facts key file: %w", err)
		}
		_, _ = fmt.Fprintf(stdout, "refunds need a fresh %s fact about the charge: report it with the API key in %s\n", devFact, *factsOut)
	} else {
		_, _ = fmt.Fprintf(stdout, "refunds need a fresh %s fact about the charge; seed again with --facts-key-out to report it\n", devFact)
	}
	return nil
}
