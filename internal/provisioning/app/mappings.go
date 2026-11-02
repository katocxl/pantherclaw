// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/provisioning/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Group is a directory group as people see it.
type Group struct {
	ID                  ids.UUID
	Issuer, DisplayName string
	MemberCount         int64
}

// DirectoryGroups lists the org's directory groups, a page after after.
func (s *Service) DirectoryGroups(ctx context.Context, after ids.UUID, limit int) ([]Group, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	var out []Group
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListAllGroups(ctx, c.Org, after, int32(limit)) //nolint:gosec // G115: at most 200
		for _, r := range rows {
			out = append(out, Group{ID: r.ID, Issuer: r.Issuer, DisplayName: r.DisplayName, MemberCount: r.MemberCount})
		}
		return err
	}, db.ReadOnly())
	return out, err
}

// Mapping gives every member of a group a role at a scope.
type Mapping struct {
	ID, Group ids.UUID
	Role      td.RoleName
	Scope     td.Scope
	CreatedBy string
	CreatedAt time.Time
}

func mappingView(org ids.OrgID, r dbq.PcGroupRoleMapping) Mapping {
	m := Mapping{ID: r.ID, Group: r.GroupID, Role: td.RoleName(r.Role), CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt}
	m.Scope.Type = td.ScopeType(r.ScopeType)
	switch {
	case r.BusinessUnitID != nil:
		m.Scope.ID = *r.BusinessUnitID
	case r.TeamID != nil:
		m.Scope.ID = *r.TeamID
	case r.EnvironmentID != nil:
		m.Scope.ID = *r.EnvironmentID
	default:
		m.Scope.ID = org.UUID()
	}
	return m
}

// ListMappings lists the org's group role mappings.
func (s *Service) ListMappings(ctx context.Context) ([]Mapping, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	var out []Mapping
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListGroupRoleMappings(ctx, c.Org)
		for _, r := range rows {
			out = append(out, mappingView(c.Org, r))
		}
		return err
	}, db.ReadOnly())
	return out, err
}

// mappingAdd is a stored mapping to add.
type mappingAdd struct {
	ID        ids.UUID     `json:"id"`
	Group     ids.UUID     `json:"group_id"`
	Role      td.RoleName  `json:"role"`
	ScopeType td.ScopeType `json:"scope_type"`
	ScopeID   ids.UUID     `json:"scope_id"`
}

func (m mappingAdd) scope(org ids.OrgID) td.Scope {
	if m.ScopeType == td.ScopeOrg {
		return td.Scope{Type: td.ScopeOrg, ID: org.UUID()}
	}
	return td.Scope{Type: m.ScopeType, ID: m.ScopeID}
}

// checkMapping refuses a role a group may not carry (HR-630) and a scope
// the caller could not bind themselves.
func checkMapping(ctx context.Context, q *dbq.Queries, c tenancy.Caller, m mappingAdd) (bu, team, env *ids.UUID, err error) {
	if err := domain.CheckMappable(m.Role, m.ScopeType); err != nil {
		return nil, nil, nil, err
	}
	if _, err := q.GroupByID(ctx, c.Org, m.Group); db.IsNoRows(err) {
		return nil, nil, nil, ErrNotFound
	} else if err != nil {
		return nil, nil, nil, err
	}
	return tenancy.BindingTarget(ctx, q, c, m.Role, m.scope(c.Org))
}

// AddMapping files giving a group's members a role at a scope (D406). The
// role must hold neither role.bind nor be Emergency Responder (HR-630). It
// needs the Enterprise edition.
func (s *Service) AddMapping(ctx context.Context, group ids.UUID, role td.RoleName, scope td.Scope) (Filed, error) {
	c, err := manager(ctx)
	if err != nil {
		return Filed{}, err
	}
	if err := s.entitled(ctx, scim); err != nil {
		return Filed{}, err
	}
	m := mappingAdd{ID: ids.NewV7(), Group: group, Role: role, ScopeType: scope.Type, ScopeID: scope.ID}
	if scope.Type == td.ScopeOrg {
		m.ScopeID = ids.UUID{}
	}
	var f Filed
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		if _, _, _, err := checkMapping(ctx, dbq.New(tx), c, m); err != nil {
			return err
		}
		f, err = s.file(ctx, tx, c, protect.SurfaceGroupMappingAdd, m.Group, ChangeMappingAdd, map[string]string{
			"group_id": m.Group.String(), "role": string(m.Role), "scope_type": string(m.ScopeType), "scope_id": m.ScopeID.String(),
		}, "group_role_mapping", m, nil)
		return err
	})
	return f, err
}

// ApplyMappingAdd is the confirmed mapping: every check runs again as the
// person who asked, then every member's bindings are re-derived.
func (s *Service) ApplyMappingAdd(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var m mappingAdd
	if err := json.Unmarshal(payload, &m); err != nil || m.ID.IsZero() || m.Group.IsZero() {
		return protect.ErrInvalid
	}
	if err := s.entitled(ctx, scim); err != nil {
		return err
	}
	q := dbq.New(tx)
	bu, team, env, err := checkMapping(ctx, q, author, m)
	if err != nil {
		return err
	}
	if _, err := q.InsertGroupRoleMapping(ctx, dbq.InsertGroupRoleMappingParams{
		OrgID: tx.OrgID(), ID: m.ID, GroupID: m.Group, Role: string(m.Role), ScopeType: string(m.ScopeType),
		BusinessUnitID: bu, TeamID: team, EnvironmentID: env, CreatedBy: author.Principal.String(),
	}); db.IsUniqueViolation(err) {
		return ErrMappingSame
	} else if err != nil {
		return err
	}
	added, removed, err := reconcileGroup(ctx, q, tx.OrgID(), m.Group)
	if err != nil {
		return err
	}
	if err := recordBy(ctx, tx, author, "scim.group_role_mapping_added", "group_role_mapping", m.ID, map[string]string{
		"group_id": m.Group.String(), "role": string(m.Role), "scope_type": string(m.ScopeType),
		"bindings_added": strconv.Itoa(added), "bindings_removed": strconv.Itoa(removed),
	}); err != nil {
		return err
	}
	return s.applied(ctx, tx, author, ChangeMappingAdd)
}

func reconcileGroup(ctx context.Context, q *dbq.Queries, org ids.OrgID, group ids.UUID) (added, removed int, err error) {
	members, err := q.GroupMemberIDs(ctx, org, group)
	if err != nil {
		return 0, 0, err
	}
	for _, u := range members {
		a, r, err := reconcile(ctx, q, org, u)
		if err != nil {
			return 0, 0, err
		}
		added, removed = added+a, removed+r
	}
	return added, removed, nil
}

// groupState is a group's state now (protect.State): the change applies
// only while the group exists.
func groupState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	var m mappingAdd
	if err := json.Unmarshal(payload, &m); err != nil || m.Group.IsZero() {
		return nil, protect.ErrInvalid
	}
	g, err := dbq.New(tx).GroupByID(ctx, tx.OrgID(), m.Group)
	if db.IsNoRows(err) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "group|%s|%s", g.ID, g.Issuer), nil
}

// RemoveMapping files taking a mapping away (D409 point 6: held too).
func (s *Service) RemoveMapping(ctx context.Context, id ids.UUID) (Filed, error) {
	c, err := manager(ctx)
	if err != nil {
		return Filed{}, err
	}
	var f Filed
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetGroupRoleMapping(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		f, err = s.file(ctx, tx, c, protect.SurfaceGroupMappingRemove, id, ChangeMappingRemove, map[string]string{
			"group_id": r.GroupID.String(), "role": r.Role, "scope_type": r.ScopeType,
		}, "group_role_mapping", payloadID{ID: id}, nil)
		return err
	})
	return f, err
}

// ApplyMappingRemove is the confirmed removal.
func (s *Service) ApplyMappingRemove(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	id, err := idOf(payload)
	if err != nil {
		return err
	}
	q := dbq.New(tx)
	r, err := q.GetGroupRoleMapping(ctx, tx.OrgID(), id)
	if db.IsNoRows(err) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if _, err := q.DeleteGroupRoleMapping(ctx, tx.OrgID(), id); err != nil {
		return err
	}
	added, removed, err := reconcileGroup(ctx, q, tx.OrgID(), r.GroupID)
	if err != nil {
		return err
	}
	if err := recordBy(ctx, tx, author, "scim.group_role_mapping_removed", "group_role_mapping", id, map[string]string{
		"group_id": r.GroupID.String(), "role": r.Role, "scope_type": r.ScopeType,
		"bindings_added": strconv.Itoa(added), "bindings_removed": strconv.Itoa(removed),
	}); err != nil {
		return err
	}
	return s.applied(ctx, tx, author, ChangeMappingRemove)
}

// mappingState is a mapping's state now (protect.State).
func mappingState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	id, err := idOf(payload)
	if err != nil {
		return nil, err
	}
	r, err := dbq.New(tx).GetGroupRoleMapping(ctx, tx.OrgID(), id)
	if db.IsNoRows(err) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "mapping|%s|%s|%s", r.ID, r.Role, r.ScopeType), nil
}
