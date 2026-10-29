// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package identityrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

var revisionState = map[string]pantherclawv1.IssuerEntryState{
	"PROPOSED":   pantherclawv1.IssuerEntryState_ISSUER_ENTRY_STATE_PROPOSED,
	"ACTIVE":     pantherclawv1.IssuerEntryState_ISSUER_ENTRY_STATE_ACTIVE,
	"SUPERSEDED": pantherclawv1.IssuerEntryState_ISSUER_ENTRY_STATE_SUPERSEDED,
	"DISABLED":   pantherclawv1.IssuerEntryState_ISSUER_ENTRY_STATE_DISABLED,
	"WITHDRAWN":  pantherclawv1.IssuerEntryState_ISSUER_ENTRY_STATE_WITHDRAWN,
}

var jobType = map[issuers.JobType]pantherclawv1.GithubJobType{
	issuers.JobWorkflow: pantherclawv1.GithubJobType_GITHUB_JOB_TYPE_WORKFLOW,
	issuers.JobReusable: pantherclawv1.GithubJobType_GITHUB_JOB_TYPE_REUSABLE_WORKFLOW,
}

func bindingFromProto(req *pantherclawv1.ProposeIssuerEntryRequest) app.Binding {
	gh, kb := req.GetGithub(), req.GetKubernetes()
	var b app.Binding
	if gl := req.GetGitlab(); gl != nil {
		b.GitLab = &issuers.GitLabBinding{
			Issuer: gl.GetIssuer(), ProjectID: gl.GetProjectId(), NamespaceID: gl.GetNamespaceId(),
			CIConfigRefURIs: gl.GetCiConfigRefUris(), CIConfigSHAs: gl.GetCiConfigShas(), Environment: gl.GetEnvironment(),
			RunnerEnvironment: gl.GetRunnerEnvironment(),
		}
	}
	if sp := req.GetSpiffe(); sp != nil {
		b.SPIFFE = &issuers.SPIFFEBinding{TrustDomain: sp.GetTrustDomain(), SPIFFEID: sp.GetSpiffeId()}
	}
	if g := req.GetGcp(); g != nil {
		b.GCP = &issuers.GCPBinding{ServiceAccountID: g.GetServiceAccountId(), ProjectID: g.GetProjectId(), InstanceID: g.GetInstanceId()}
	}
	if aw := req.GetAws(); aw != nil {
		b.AWS = &issuers.AWSBinding{AccountID: aw.GetAccountId(), RoleName: aw.GetRoleName()}
	}
	if az := req.GetAzureMi(); az != nil {
		b.AzureMI = &issuers.AzureMIBinding{
			TenantID: az.GetTenantId(), AppID: az.GetAppId(), ObjectID: az.GetObjectId(), ResourceID: az.GetResourceId(),
		}
	}
	if gh != nil {
		g := issuers.GitHubBinding{
			RepositoryID: gh.GetRepositoryId(), RepositoryOwnerID: gh.GetRepositoryOwnerId(),
			WorkflowRefs: gh.GetWorkflowRefs(), WorkflowSHAs: gh.GetWorkflowShas(), Environment: gh.GetEnvironment(),
			RunnerEnvironment: gh.GetRunnerEnvironment(),
		}
		for k, v := range jobType {
			if v == gh.GetJobType() {
				g.JobType = k
			}
		}
		b.GitHub = &g
	}
	if kb != nil {
		b.Kubernetes = &issuers.KubernetesBinding{
			Cluster: kb.GetCluster(), Namespace: kb.GetNamespace(), ServiceAccountName: kb.GetServiceAccountName(),
			ServiceAccountUID: kb.GetServiceAccountUid(), ImageRepositories: kb.GetImageRepositories(), ImageDigests: kb.GetImageDigests(),
		}
	}
	return b
}

func revisionProto(r app.Revision) *pantherclawv1.IssuerRevision {
	out := &pantherclawv1.IssuerRevision{
		Id: r.ID.String(), EntryId: r.EntryID.String(), Revision: int32(r.Revision), AgentId: r.AgentID.String(), //nolint:gosec // G115: small
		Issuer: r.Issuer, Audience: r.Audience, Algorithms: r.Algorithms, AutoAdmit: r.AutoAdmit, Widening: r.Widening,
		State: revisionState[r.State], ProposedBy: r.ProposedBy, ProposeTime: timestamppb.New(r.ProposedAt),
		ActivatedBy: r.ActivatedBy, ActivateTime: tsp(r.ActivatedAt), ClosedBy: r.ClosedBy, CloseTime: tsp(r.ClosedAt),
	}
	if g := r.Binding.GitHub; g != nil {
		out.Kind = pantherclawv1.IssuerKind_ISSUER_KIND_GITHUB_ACTIONS
		out.Binding = &pantherclawv1.IssuerRevision_Github{Github: &pantherclawv1.GithubBinding{
			RepositoryId: g.RepositoryID, RepositoryOwnerId: g.RepositoryOwnerID, JobType: jobType[g.JobType],
			WorkflowRefs: g.WorkflowRefs, WorkflowShas: g.WorkflowSHAs, Environment: g.Environment, RunnerEnvironment: g.RunnerEnvironment,
		}}
	}
	if g := r.Binding.GitLab; g != nil {
		out.Kind = pantherclawv1.IssuerKind_ISSUER_KIND_GITLAB_CI
		out.Binding = &pantherclawv1.IssuerRevision_Gitlab{Gitlab: &pantherclawv1.GitlabBinding{
			Issuer: g.Issuer, ProjectId: g.ProjectID, NamespaceId: g.NamespaceID, CiConfigRefUris: g.CIConfigRefURIs,
			CiConfigShas: g.CIConfigSHAs, Environment: g.Environment, RunnerEnvironment: g.RunnerEnvironment,
		}}
	}
	if sp := r.Binding.SPIFFE; sp != nil {
		out.Kind = pantherclawv1.IssuerKind_ISSUER_KIND_SPIFFE_JWT
		out.Binding = &pantherclawv1.IssuerRevision_Spiffe{Spiffe: &pantherclawv1.SpiffeBinding{TrustDomain: sp.TrustDomain, SpiffeId: sp.SPIFFEID}}
	}
	if g := r.Binding.GCP; g != nil {
		out.Kind = pantherclawv1.IssuerKind_ISSUER_KIND_GCP_WORKLOAD
		out.Binding = &pantherclawv1.IssuerRevision_Gcp{Gcp: &pantherclawv1.GcpBinding{
			ServiceAccountId: g.ServiceAccountID, ProjectId: g.ProjectID, InstanceId: g.InstanceID,
		}}
	}
	if aw := r.Binding.AWS; aw != nil {
		out.Kind = pantherclawv1.IssuerKind_ISSUER_KIND_AWS_IAM
		out.Binding = &pantherclawv1.IssuerRevision_Aws{Aws: &pantherclawv1.AwsBinding{AccountId: aw.AccountID, RoleName: aw.RoleName}}
	}
	if az := r.Binding.AzureMI; az != nil {
		out.Kind = pantherclawv1.IssuerKind_ISSUER_KIND_AZURE_MI
		out.Binding = &pantherclawv1.IssuerRevision_AzureMi{AzureMi: &pantherclawv1.AzureMiBinding{
			TenantId: az.TenantID, AppId: az.AppID, ObjectId: az.ObjectID, ResourceId: az.ResourceID,
		}}
	}
	if k := r.Binding.Kubernetes; k != nil {
		out.Kind = pantherclawv1.IssuerKind_ISSUER_KIND_KUBERNETES
		out.Binding = &pantherclawv1.IssuerRevision_Kubernetes{Kubernetes: &pantherclawv1.KubernetesBinding{
			Cluster: k.Cluster, Namespace: k.Namespace, ServiceAccountName: k.ServiceAccountName,
			ServiceAccountUid: k.ServiceAccountUID, ImageRepositories: k.ImageRepositories, ImageDigests: k.ImageDigests,
		}}
	}
	return out
}

// ProposeIssuerEntry implements IdentityServiceHandler.
func (s *Identity) ProposeIssuerEntry(ctx context.Context, req *pantherclawv1.ProposeIssuerEntryRequest) (*pantherclawv1.ProposeIssuerEntryResponse, error) {
	var entry ids.UUID
	if req.GetEntryId() != "" {
		var err error
		if entry, err = parseID(req.GetEntryId()); err != nil {
			return nil, err
		}
	}
	agent, err := parseID(req.GetAgentId())
	if err != nil {
		return nil, err
	}
	r, err := s.svc.ProposeIssuer(ctx, app.ProposeInput{
		EntryID: entry, AgentID: agent, Binding: bindingFromProto(req),
		AutoAdmit: req.GetAutoAdmit(), Reason: req.GetReason(),
	}, s.clusters)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ProposeIssuerEntryResponse{Revision: revisionProto(r)}, nil
}

// ActivateIssuerEntry implements IdentityServiceHandler.
func (s *Identity) ActivateIssuerEntry(ctx context.Context, req *pantherclawv1.ActivateIssuerEntryRequest) (*pantherclawv1.ActivateIssuerEntryResponse, error) {
	entry, err := parseID(req.GetEntryId())
	if err != nil {
		return nil, err
	}
	r, err := s.svc.ActivateIssuer(ctx, entry, int(req.GetRevision()), req.GetConfirmReusableRefsProtected())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ActivateIssuerEntryResponse{Revision: revisionProto(r)}, nil
}

// WithdrawIssuerProposal implements IdentityServiceHandler.
func (s *Identity) WithdrawIssuerProposal(ctx context.Context, req *pantherclawv1.WithdrawIssuerProposalRequest) (*pantherclawv1.WithdrawIssuerProposalResponse, error) {
	entry, err := parseID(req.GetEntryId())
	if err != nil {
		return nil, err
	}
	r, err := s.svc.WithdrawIssuer(ctx, entry, int(req.GetRevision()))
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.WithdrawIssuerProposalResponse{Revision: revisionProto(r)}, nil
}

// DisableIssuerEntry implements IdentityServiceHandler.
func (s *Identity) DisableIssuerEntry(ctx context.Context, req *pantherclawv1.DisableIssuerEntryRequest) (*pantherclawv1.DisableIssuerEntryResponse, error) {
	entry, err := parseID(req.GetEntryId())
	if err != nil {
		return nil, err
	}
	r, err := s.svc.DisableIssuer(ctx, entry, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DisableIssuerEntryResponse{Revision: revisionProto(r)}, nil
}

// ListIssuerEntries implements IdentityServiceHandler.
func (s *Identity) ListIssuerEntries(ctx context.Context, req *pantherclawv1.ListIssuerEntriesRequest) (*pantherclawv1.ListIssuerEntriesResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	var agent ids.UUID
	if req.AgentId != nil {
		if agent, err = parseID(req.GetAgentId()); err != nil {
			return nil, err
		}
	}
	items, next, err := s.svc.ListIssuers(ctx, agent, pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListIssuerEntriesResponse{NextPageToken: next}
	for _, r := range items {
		out.Entries = append(out.Entries, revisionProto(r))
	}
	return out, nil
}

// GetIssuerEntry implements IdentityServiceHandler.
func (s *Identity) GetIssuerEntry(ctx context.Context, req *pantherclawv1.GetIssuerEntryRequest) (*pantherclawv1.GetIssuerEntryResponse, error) {
	entry, err := parseID(req.GetEntryId())
	if err != nil {
		return nil, err
	}
	revs, err := s.svc.GetIssuer(ctx, entry)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetIssuerEntryResponse{}
	for _, r := range revs {
		out.Revisions = append(out.Revisions, revisionProto(r))
	}
	return out, nil
}
