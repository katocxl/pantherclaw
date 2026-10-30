// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"log/slog"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ListRoles returns the role catalog. It is not secret: any authenticated
// principal may read it.
func (a *Access) ListRoles(ctx context.Context) ([]td.Role, error) {
	if _, err := CallerFrom(ctx); err != nil {
		return nil, err
	}
	return td.Roles(), nil
}

// ListRoleBindings lists role bindings, optionally of one principal.
func (a *Access) ListRoleBindings(ctx context.Context, pr page.Request, principal *td.PrincipalRef) (Page[RoleBinding], error) {
	var out Page[RoleBinding]
	err := inOrg(ctx, a.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		if err := c.Require(td.PermRoleRead, td.OrgPath(c.Org)); err != nil {
			return err
		}
		arg := dbq.ListRoleBindingsParams{OrgID: c.Org, After: pr.After, PageLimit: pr.Limit()}
		if principal != nil {
			id := principal.ID
			switch principal.Kind {
			case td.KindUser:
				arg.UserID = &id
			case td.KindServiceAccount:
				arg.ServiceAccountID = &id
			case td.KindSupport:
				// Support roles are never bound (G0 M13 D38), so a support
				// principal has no binding rows; never fall through to an
				// unfiltered listing of every binding.
				return nil
			}
		}
		rows, err := q.ListRoleBindings(ctx, arg)
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.PcRoleBinding) ids.UUID { return r.ID })
		for _, r := range rows {
			out.Items = append(out.Items, bindingView(c.Org, r))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// ErrDelegatedAdminEdition refuses binding the Scope Admin role below the
// Enterprise edition (F584, G0 M18 D159). Existing bindings keep their
// ceiling and can always be removed.
var ErrDelegatedAdminEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
	"delegated administration needs the Enterprise edition")

// checkDelegatedAdmin applies the Scope Admin edition gate.
func (a *Access) checkDelegatedAdmin(ctx context.Context, role td.RoleName) error {
	if role != td.RoleScopeAdmin || a.ents == nil {
		return nil
	}
	ent, err := a.ents.Current(ctx)
	if err != nil {
		return err
	}
	if !ent.DelegatedAdmin() {
		return ErrDelegatedAdminEdition
	}
	return nil
}

// CreateRoleBinding grants role to principal at scope. The role must allow
// the scope type and, for service accounts, contain no human-only
// permission; the principal and the scope must exist and be active. The
// caller binds only within its ceiling: org-level role.bind binds anything,
// otherwise role.bind on the scope and a binding of the same role at the
// scope or an ancestor (G0 M18 D152, HR-472, HR-473). A caller granting
// itself a role is allowed and audited with self_grant=true (ADR-0016).
func (a *Access) CreateRoleBinding(ctx context.Context, role td.RoleName, principal td.PrincipalRef, scope td.Scope) (RoleBinding, bool, error) {
	if _, err := td.CheckBindable(role, principal.Kind, scope.Type); err != nil {
		return RoleBinding{}, false, err
	}
	if err := a.checkDelegatedAdmin(ctx, role); err != nil {
		return RoleBinding{}, false, err
	}
	var out RoleBinding
	var self bool
	err := inOrg(ctx, a.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		if !c.CanAnywhere(td.PermRoleBind) {
			return td.ErrPermissionDenied(td.PermRoleBind)
		}
		arg := dbq.InsertRoleBindingParams{
			OrgID: c.Org, ID: ids.NewV7(), Role: string(role), ScopeType: string(scope.Type), CreatedBy: c.Principal.String(),
		}
		if err := checkPrincipal(ctx, q, c.Org, principal, &arg); err != nil {
			return err
		}
		if err := checkScope(ctx, q, c.Org, scope, &arg); err != nil {
			return err
		}
		path, err := scopePath(ctx, q, c.Org, scope)
		if err != nil {
			return err
		}
		if err := c.CheckBindCeiling(role, path); err != nil {
			return err
		}
		r, err := q.InsertRoleBinding(ctx, arg)
		if db.IsUniqueViolation(err) {
			return ErrBindingExists
		} else if err != nil {
			return err
		}
		out = bindingView(c.Org, r)
		self = td.SelfGrant(c.Principal, principal)
		if self {
			a.log.WarnContext(ctx, "access.self_grant", slog.String("role", string(role)),
				slog.String("principal", principal.String()))
		}
		return record(ctx, tx, c, "access.role_bound", "role_binding", r.ID, map[string]string{
			"role": string(role), "principal": principal.String(), "scope_type": string(scope.Type),
			"scope": scope.ID.String(), "self_grant": strconv.FormatBool(self),
		})
	})
	return out, self, err
}

func checkPrincipal(ctx context.Context, q *dbq.Queries, org ids.OrgID, p td.PrincipalRef, arg *dbq.InsertRoleBindingParams) error {
	id := p.ID
	switch p.Kind {
	case td.KindUser:
		u, err := q.ShareUser(ctx, org, id)
		if err != nil {
			return notFound(err, ErrUserNotFound)
		}
		if td.AccountState(u.State) != td.Enabled {
			return ErrPrincipalDisabled
		}
		arg.UserID = &id
	case td.KindServiceAccount:
		sa, err := q.ShareServiceAccount(ctx, org, id)
		if err != nil {
			return notFound(err, ErrServiceAccountNotFound)
		}
		if err := notAutomationIdentity(ctx, q, org, id); err != nil {
			return err
		}
		if td.AccountState(sa.State) != td.Enabled {
			return ErrPrincipalDisabled
		}
		arg.ServiceAccountID = &id
	case td.KindSupport:
		// Nothing can be bound to a support principal (G0 M13 D38).
		return td.ErrUnknownRole
	default:
		return td.ErrUnknownRole
	}
	return nil
}

func checkScope(ctx context.Context, q *dbq.Queries, org ids.OrgID, s td.Scope, arg *dbq.InsertRoleBindingParams) error {
	id := s.ID
	var state string
	var err error
	switch s.Type {
	case td.ScopeOrg:
		if s.ID != org.UUID() && !s.ID.IsZero() {
			return ErrOrgNotFound
		}
		return nil
	case td.ScopeBusinessUnit:
		state, err = q.ShareBusinessUnit(ctx, org, id)
		err = notFound(err, ErrBusinessUnitNotFound)
		arg.BusinessUnitID = &id
	case td.ScopeTeam:
		state, err = q.ShareTeam(ctx, org, id)
		err = notFound(err, ErrTeamNotFound)
		arg.TeamID = &id
	case td.ScopeEnvironment:
		state, err = q.ShareEnvironment(ctx, org, id)
		err = notFound(err, ErrEnvironmentNotFound)
		arg.EnvironmentID = &id
	default:
		return td.ErrScopeNotAllowed
	}
	if err != nil {
		return err
	}
	if td.State(state) != td.Active {
		return ErrArchived
	}
	return nil
}

// DeleteRoleBinding removes a binding. Removing the last active Org Admin is
// refused. Unbinding follows the same ceiling as binding (G0 M18 D152,
// HR-474).
func (a *Access) DeleteRoleBinding(ctx context.Context, id td.RoleBindingID) error {
	return inOrg(ctx, a.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		if !c.CanAnywhere(td.PermRoleBind) {
			return td.ErrPermissionDenied(td.PermRoleBind)
		}
		guard, err := guardAdmins(ctx, q, c.Org)
		if err != nil {
			return err
		}
		r, err := q.GetRoleBinding(ctx, c.Org, id.UUID())
		if err != nil {
			return notFound(err, ErrBindingNotFound)
		}
		path, err := scopePath(ctx, q, c.Org, bindingScope(c.Org, r))
		if err != nil {
			return err
		}
		if err := c.CheckBindCeiling(td.RoleName(r.Role), path); err != nil {
			return err
		}
		if _, err := q.DeleteRoleBinding(ctx, c.Org, r.ID); err != nil {
			return err
		}
		if err := guard(ctx); err != nil {
			return err
		}
		p := bindingPrincipal(r)
		return record(ctx, tx, c, "access.role_unbound", "role_binding", r.ID, map[string]string{
			"role": r.Role, "principal": p.String(), "scope_type": r.ScopeType,
			"self_grant": strconv.FormatBool(td.SelfGrant(c.Principal, p)),
		})
	})
}
