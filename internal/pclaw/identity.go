// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

var jobTypes = map[string]pantherclawv1.GithubJobType{
	"workflow":          pantherclawv1.GithubJobType_GITHUB_JOB_TYPE_WORKFLOW,
	"reusable-workflow": pantherclawv1.GithubJobType_GITHUB_JOB_TYPE_REUSABLE_WORKFLOW,
}

func identityCommands() map[string]command {
	return map[string]command{
		"instance list": rpc("instance list AGENT [--state S,...]", 1, func(fs *flag.FlagSet) call {
			var states list
			fs.Var(&states, "state", "only these states (pending_admission, admitted, rejected, revoked, expired)")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				st, err := enumList[pantherclawv1.InstanceState](states, "INSTANCE_STATE_", pantherclawv1.InstanceState_value)
				if err != nil {
					return nil, err
				}
				return c.identity.ListInstances(ctx, &pantherclawv1.ListInstancesRequest{AgentId: a[0], PageSize: size(n), PageToken: *tok, States: st})
			}
		}),
		"instance get": rpc("instance get ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.identity.GetInstance(ctx, &pantherclawv1.GetInstanceRequest{Id: a[0]})
			}
		}),
		"instance admit": rpc("instance admit ID --fingerprint FP", 1, func(fs *flag.FlagSet) call {
			fp := fs.String("fingerprint", "", "the key fingerprint the workload printed; it must match")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.identity.AdmitInstance(ctx, &pantherclawv1.AdmitInstanceRequest{Id: a[0], Fingerprint: *fp})
			}
		}),
		"instance reject": rpc("instance reject ID --reason R", 1, func(fs *flag.FlagSet) call {
			reason := fs.String("reason", "", "why")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.identity.RejectInstance(ctx, &pantherclawv1.RejectInstanceRequest{Id: a[0], Reason: *reason})
			}
		}),
		"instance revoke": rpc("instance revoke ID --reason R", 1, func(fs *flag.FlagSet) call {
			reason := fs.String("reason", "", "why")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.identity.RevokeInstance(ctx, &pantherclawv1.RevokeInstanceRequest{Id: a[0], Reason: *reason})
			}
		}),
		"issuer propose-github": rpc("issuer propose-github --agent ID --repository-id N --owner-id N --workflow-ref REF... [--job-type workflow|reusable-workflow] [--workflow-sha SHA...] [--environment E] [--runner github-hosted|self-hosted] [--auto-admit] [--entry ID] --reason R", 0, func(fs *flag.FlagSet) call {
			agent, entry, reason := fs.String("agent", "", "agent the entry binds to"), fs.String("entry", "", "revise this entry"), fs.String("reason", "", "why")
			repo, owner := fs.String("repository-id", "", "numeric repository id"), fs.String("owner-id", "", "numeric repository owner id")
			job, env, runner := fs.String("job-type", "workflow", "workflow or reusable-workflow"), fs.String("environment", "", "pin a deployment environment"),
				fs.String("runner", "", "pin github-hosted or self-hosted runners")
			auto := fs.Bool("auto-admit", false, "admit matching workloads without an owner (needs activation by an Identity Publisher)")
			var refs, shas list
			fs.Var(&refs, "workflow-ref", "owner/repo/.github/workflows/file.yml@refs/heads/main (repeatable)")
			fs.Var(&shas, "workflow-sha", "pin an exact workflow revision (repeatable)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				jt, ok := jobTypes[*job]
				if !ok {
					return nil, fmt.Errorf("--job-type must be workflow or reusable-workflow")
				}
				return c.identity.ProposeIssuerEntry(ctx, &pantherclawv1.ProposeIssuerEntryRequest{
					EntryId: *entry, AgentId: *agent, AutoAdmit: *auto, Reason: *reason,
					Binding: &pantherclawv1.ProposeIssuerEntryRequest_Github{Github: &pantherclawv1.GithubBinding{
						RepositoryId: *repo, RepositoryOwnerId: *owner, JobType: jt, WorkflowRefs: refs, WorkflowShas: shas,
						Environment: *env, RunnerEnvironment: *runner,
					}},
				})
			}
		}),
		"issuer propose-gitlab": rpc("issuer propose-gitlab --agent ID [--issuer URL] --project-id N --namespace-id N --ci-config-ref-uri URI... [--ci-config-sha SHA...] [--environment E] [--runner gitlab-hosted|self-hosted] [--auto-admit] [--entry ID] --reason R", 0, func(fs *flag.FlagSet) call {
			agent, entry, reason := fs.String("agent", "", "agent the entry binds to"), fs.String("entry", "", "revise this entry"), fs.String("reason", "", "why")
			issuer := fs.String("issuer", "https://gitlab.com", "GitLab instance from the server configuration (identity.gitlab_issuers)")
			project, namespace := fs.String("project-id", "", "numeric project id"), fs.String("namespace-id", "", "numeric namespace (group) id")
			env, runner := fs.String("environment", "", "pin a deployment environment"), fs.String("runner", "", "pin gitlab-hosted or self-hosted runners")
			auto := fs.Bool("auto-admit", false, "admit matching workloads without an owner (needs activation by an Identity Publisher)")
			var refs, shas list
			fs.Var(&refs, "ci-config-ref-uri", "gitlab.com/group/project//.gitlab-ci.yml@refs/heads/main (repeatable)")
			fs.Var(&shas, "ci-config-sha", "pin an exact pipeline definition revision (repeatable)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.identity.ProposeIssuerEntry(ctx, &pantherclawv1.ProposeIssuerEntryRequest{
					EntryId: *entry, AgentId: *agent, AutoAdmit: *auto, Reason: *reason,
					Binding: &pantherclawv1.ProposeIssuerEntryRequest_Gitlab{Gitlab: &pantherclawv1.GitlabBinding{
						Issuer: *issuer, ProjectId: *project, NamespaceId: *namespace, CiConfigRefUris: refs, CiConfigShas: shas,
						Environment: *env, RunnerEnvironment: *runner,
					}},
				})
			}
		}),
		"issuer propose-spiffe": rpc("issuer propose-spiffe --agent ID --trust-domain TD --spiffe-id spiffe://TD/PATH [--auto-admit] [--entry ID] --reason R", 0, func(fs *flag.FlagSet) call {
			agent, entry, reason := fs.String("agent", "", "agent the entry binds to"), fs.String("entry", "", "revise this entry"), fs.String("reason", "", "why")
			td := fs.String("trust-domain", "", "trust domain from the server configuration (identity.spiffe_trust_domains)")
			id := fs.String("spiffe-id", "", "the workload's exact SPIFFE ID")
			auto := fs.Bool("auto-admit", false, "admit matching workloads without an owner (needs activation by an Identity Publisher)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.identity.ProposeIssuerEntry(ctx, &pantherclawv1.ProposeIssuerEntryRequest{
					EntryId: *entry, AgentId: *agent, AutoAdmit: *auto, Reason: *reason,
					Binding: &pantherclawv1.ProposeIssuerEntryRequest_Spiffe{Spiffe: &pantherclawv1.SpiffeBinding{
						TrustDomain: *td, SpiffeId: *id,
					}},
				})
			}
		}),
		"issuer propose-gcp": rpc("issuer propose-gcp --agent ID --service-account-id N [--project-id P] [--instance-id N] [--auto-admit] [--entry ID] --reason R", 0, func(fs *flag.FlagSet) call {
			agent, entry, reason := fs.String("agent", "", "agent the entry binds to"), fs.String("entry", "", "revise this entry"), fs.String("reason", "", "why")
			sa := fs.String("service-account-id", "", "the service account's numeric unique id (not its email)")
			project, instance := fs.String("project-id", "", "pin a Compute Engine project"), fs.String("instance-id", "", "pin a numeric Compute Engine instance id")
			auto := fs.Bool("auto-admit", false, "admit matching workloads without an owner (needs activation by an Identity Publisher)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.identity.ProposeIssuerEntry(ctx, &pantherclawv1.ProposeIssuerEntryRequest{
					EntryId: *entry, AgentId: *agent, AutoAdmit: *auto, Reason: *reason,
					Binding: &pantherclawv1.ProposeIssuerEntryRequest_Gcp{Gcp: &pantherclawv1.GcpBinding{
						ServiceAccountId: *sa, ProjectId: *project, InstanceId: *instance,
					}},
				})
			}
		}),
		"issuer propose-aws": rpc("issuer propose-aws --agent ID --account-id N --role-name NAME [--auto-admit] [--entry ID] --reason R", 0, func(fs *flag.FlagSet) call {
			agent, entry, reason := fs.String("agent", "", "agent the entry binds to"), fs.String("entry", "", "revise this entry"), fs.String("reason", "", "why")
			account, role := fs.String("account-id", "", "12-digit AWS account id"), fs.String("role-name", "", "IAM role name whose sessions attest")
			auto := fs.Bool("auto-admit", false, "admit matching workloads without an owner (needs activation by an Identity Publisher)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.identity.ProposeIssuerEntry(ctx, &pantherclawv1.ProposeIssuerEntryRequest{
					EntryId: *entry, AgentId: *agent, AutoAdmit: *auto, Reason: *reason,
					Binding: &pantherclawv1.ProposeIssuerEntryRequest_Aws{Aws: &pantherclawv1.AwsBinding{AccountId: *account, RoleName: *role}},
				})
			}
		}),
		"issuer propose-azure-mi": rpc("issuer propose-azure-mi --agent ID --tenant-id GUID --app-id GUID --object-id GUID [--auto-admit] [--entry ID] --reason R", 0, func(fs *flag.FlagSet) call {
			agent, entry, reason := fs.String("agent", "", "agent the entry binds to"), fs.String("entry", "", "revise this entry"), fs.String("reason", "", "why")
			tenant, appID := fs.String("tenant-id", "", "Entra tenant id"), fs.String("app-id", "", "Entra app id pinned for this org (identity.entra_apps)")
			object := fs.String("object-id", "", "the managed identity's object (principal) id")
			auto := fs.Bool("auto-admit", false, "admit matching workloads without an owner (needs activation by an Identity Publisher)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.identity.ProposeIssuerEntry(ctx, &pantherclawv1.ProposeIssuerEntryRequest{
					EntryId: *entry, AgentId: *agent, AutoAdmit: *auto, Reason: *reason,
					Binding: &pantherclawv1.ProposeIssuerEntryRequest_AzureMi{AzureMi: &pantherclawv1.AzureMiBinding{
						TenantId: *tenant, AppId: *appID, ObjectId: *object,
					}},
				})
			}
		}),
		"issuer propose-entra-agent": rpc("issuer propose-entra-agent --agent ID --tenant-id GUID --app-id GUID --object-id GUID [--auto-admit] [--entry ID] --reason R", 0, func(fs *flag.FlagSet) call {
			agent, entry, reason := fs.String("agent", "", "agent the entry binds to"), fs.String("entry", "", "revise this entry"), fs.String("reason", "", "why")
			tenant, appID := fs.String("tenant-id", "", "Entra tenant id"), fs.String("app-id", "", "Entra app id pinned for this org (identity.entra_apps)")
			object := fs.String("object-id", "", "the agent identity's service principal object id")
			auto := fs.Bool("auto-admit", false, "admit matching workloads without an owner (needs activation by an Identity Publisher)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.identity.ProposeIssuerEntry(ctx, &pantherclawv1.ProposeIssuerEntryRequest{
					EntryId: *entry, AgentId: *agent, AutoAdmit: *auto, Reason: *reason,
					Binding: &pantherclawv1.ProposeIssuerEntryRequest_EntraAgent{EntraAgent: &pantherclawv1.EntraAgentBinding{
						TenantId: *tenant, AppId: *appID, ObjectId: *object,
					}},
				})
			}
		}),
		"issuer propose-kubernetes": rpc("issuer propose-kubernetes --agent ID --cluster NAME --namespace NS --service-account NAME --service-account-uid UID [--image-repository R...] [--image-digest D...] [--auto-admit] [--entry ID] --reason R", 0, func(fs *flag.FlagSet) call {
			agent, entry, reason := fs.String("agent", "", "agent the entry binds to"), fs.String("entry", "", "revise this entry"), fs.String("reason", "", "why")
			cluster, ns := fs.String("cluster", "", "cluster name from the server configuration"), fs.String("namespace", "", "namespace")
			sa, uid := fs.String("service-account", "", "service account name"), fs.String("service-account-uid", "", "service account UID")
			auto := fs.Bool("auto-admit", false, "admit matching workloads without an owner (needs activation by an Identity Publisher)")
			var repos, digests list
			fs.Var(&repos, "image-repository", "allowed image repository (repeatable)")
			fs.Var(&digests, "image-digest", "allowed image digest sha256:… (repeatable)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.identity.ProposeIssuerEntry(ctx, &pantherclawv1.ProposeIssuerEntryRequest{
					EntryId: *entry, AgentId: *agent, AutoAdmit: *auto, Reason: *reason,
					Binding: &pantherclawv1.ProposeIssuerEntryRequest_Kubernetes{Kubernetes: &pantherclawv1.KubernetesBinding{
						Cluster: *cluster, Namespace: *ns, ServiceAccountName: *sa, ServiceAccountUid: *uid,
						ImageRepositories: repos, ImageDigests: digests,
					}},
				})
			}
		}),
		"issuer activate": rpc("issuer activate ENTRY REVISION [--confirm-reusable-refs-protected]", 2, func(fs *flag.FlagSet) call {
			confirm := fs.Bool("confirm-reusable-refs-protected", false, "confirm every reusable workflow ref is a protected branch or tag")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				rev, err := revision(a[1])
				if err != nil {
					return nil, err
				}
				return c.identity.ActivateIssuerEntry(ctx, &pantherclawv1.ActivateIssuerEntryRequest{
					EntryId: a[0], Revision: rev, ConfirmReusableRefsProtected: *confirm,
				})
			}
		}),
		"issuer withdraw": rpc("issuer withdraw ENTRY REVISION", 2, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				rev, err := revision(a[1])
				if err != nil {
					return nil, err
				}
				return c.identity.WithdrawIssuerProposal(ctx, &pantherclawv1.WithdrawIssuerProposalRequest{EntryId: a[0], Revision: rev})
			}
		}),
		"issuer disable": rpc("issuer disable ENTRY --reason R", 1, func(fs *flag.FlagSet) call {
			reason := fs.String("reason", "", "why")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.identity.DisableIssuerEntry(ctx, &pantherclawv1.DisableIssuerEntryRequest{EntryId: a[0], Reason: *reason})
			}
		}),
		"issuer list": rpc("issuer list [--agent ID]", 0, func(fs *flag.FlagSet) call {
			agent := fs.String("agent", "", "only this agent")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.identity.ListIssuerEntries(ctx, &pantherclawv1.ListIssuerEntriesRequest{PageSize: size(n), PageToken: *tok, AgentId: optStr(*agent)})
			}
		}),
		"issuer get": rpc("issuer get ENTRY", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.identity.GetIssuerEntry(ctx, &pantherclawv1.GetIssuerEntryRequest{EntryId: a[0]})
			}
		}),
		"run start": rpc("run start AGENT [--instance ID] [--grant ID] [--task REF] [--ttl MINUTES] [--subject-token-file FILE --subject-token-type id_token|access_token]", 1, func(fs *flag.FlagSet) call {
			inst, task, ttl := fs.String("instance", "", "bind to this admitted instance"), fs.String("task", "", "untrusted task label"),
				fs.Int("ttl", 0, "lifetime in minutes (default 480, at most 1440)")
			grant := fs.String("grant", "", "the grant whose authority the run uses (without one its actions are denied)")
			subjectFile, subjectType := fs.String("subject-token-file", "", "act for the user this provider token proves (needs run.represent)"),
				fs.String("subject-token-type", "id_token", "id_token or access_token")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				req := &pantherclawv1.StartRunRequest{
					AgentId: a[0], InstanceId: optStr(*inst), GrantId: optStr(*grant), TaskRef: *task, TtlMinutes: int32(min(max(*ttl, 0), 1440)),
				}
				if *subjectFile != "" {
					tok, err := readSecret(*subjectFile)
					if err != nil {
						return nil, err
					}
					req.SubjectToken = tok
					switch *subjectType {
					case "id_token":
						req.SubjectTokenType = pantherclawv1.SubjectTokenType_SUBJECT_TOKEN_TYPE_ID_TOKEN
					case "access_token":
						req.SubjectTokenType = pantherclawv1.SubjectTokenType_SUBJECT_TOKEN_TYPE_ACCESS_TOKEN
					default:
						return nil, fmt.Errorf("--subject-token-type must be id_token or access_token")
					}
				}
				return c.runs.StartRun(ctx, req)
			}
		}),
		"run get": rpc("run get ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.runs.GetRun(ctx, &pantherclawv1.GetRunRequest{Id: a[0]})
			}
		}),
		"run list": rpc("run list [--agent ID] [--state S,...]", 0, func(fs *flag.FlagSet) call {
			agent := fs.String("agent", "", "only this agent")
			var states list
			fs.Var(&states, "state", "only these states (active, ended, cancelled, expired, revoked)") //nolint:misspell // API value
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				st, err := enumList[pantherclawv1.RunState](states, "RUN_STATE_", pantherclawv1.RunState_value)
				if err != nil {
					return nil, err
				}
				return c.runs.ListRuns(ctx, &pantherclawv1.ListRunsRequest{PageSize: size(n), PageToken: *tok, AgentId: optStr(*agent), States: st})
			}
		}),
		"run end": rpc("run end ID --reason R", 1, func(fs *flag.FlagSet) call {
			reason := fs.String("reason", "done", "why (at most 64 characters)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.runs.EndRun(ctx, &pantherclawv1.EndRunRequest{Id: a[0], Reason: *reason})
			}
		}),
	}
}

func revision(s string) (int32, error) {
	var n int32
	if _, err := fmt.Sscan(s, &n); err != nil || n < 1 {
		return 0, fmt.Errorf("REVISION must be a positive number")
	}
	return n, nil
}
