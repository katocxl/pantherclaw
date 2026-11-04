// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"context"
	"errors"
	"slices"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/provisioning/domain"
	"github.com/katocxl/pantherclaw/internal/provisioning/ports"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// MaxMembers bounds the members one group change names.
const MaxMembers = 1000

func (s *Service) groupOut(ctx context.Context, q *dbq.Queries, g dbq.PcGroup) (ports.Group, error) {
	members, err := q.GroupMemberIDs(ctx, g.OrgID, g.ID)
	if err != nil {
		return ports.Group{}, err
	}
	out := ports.Group{
		ID: g.ID.String(), DisplayName: g.DisplayName, ExternalID: deref(g.ExternalID), CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt,
		Members: make([]string, len(members)),
	}
	for i, m := range members {
		out.Members[i] = m.String()
	}
	return out, nil
}

// ListGroups lists the token issuer's groups.
func (s *Service) ListGroups(ctx context.Context, pt ports.Token, f ports.GroupFilter, p ports.Page) (ports.Groups, error) {
	var out ports.Groups
	err := s.inDir(ctx, pt, func(ctx context.Context, _ db.TenantTx, q *dbq.Queries, t token) error {
		name, ext := optional(f.DisplayName), optional(f.ExternalID)
		n, err := q.CountDirectoryGroups(ctx, dbq.CountDirectoryGroupsParams{OrgID: t.org, Issuer: t.Issuer, DisplayName: name, ExternalID: ext})
		if err != nil {
			return err
		}
		out.Total = int(n)
		offset, limit := clamp(p)
		if limit == 0 {
			return nil
		}
		rows, err := q.ListDirectoryGroups(ctx, dbq.ListDirectoryGroupsParams{
			OrgID: t.org, Issuer: t.Issuer, DisplayName: name, ExternalID: ext, PageOffset: offset, PageLimit: limit,
		})
		if err != nil {
			return err
		}
		for _, r := range rows {
			g, err := s.groupOut(ctx, q, r)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, g)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

func lockGroup(ctx context.Context, q *dbq.Queries, t token, id string) (dbq.PcGroup, error) {
	g, err := ids.ParseUUID(id)
	if err != nil {
		return dbq.PcGroup{}, ports.ErrNotFound
	}
	r, err := q.LockGroup(ctx, t.org, t.Issuer, g)
	if db.IsNoRows(err) {
		return dbq.PcGroup{}, ports.ErrNotFound
	}
	return r, err
}

// GetGroup returns one group of the token's issuer.
func (s *Service) GetGroup(ctx context.Context, pt ports.Token, id string) (ports.Group, error) {
	var out ports.Group
	err := s.inDir(ctx, pt, func(ctx context.Context, _ db.TenantTx, q *dbq.Queries, t token) error {
		g, err := lockGroup(ctx, q, t, id)
		if err != nil {
			return err
		}
		out, err = s.groupOut(ctx, q, g)
		return err
	})
	return out, err
}

// members resolves user ids to users of the token's issuer that SCIM has
// not deleted: a group holds no one else (HR-629).
func members(ctx context.Context, q *dbq.Queries, t token, in []string) ([]ids.UUID, error) {
	if len(in) > MaxMembers {
		return nil, ports.ErrInvalid
	}
	out := make([]ids.UUID, 0, len(in))
	for _, s := range in {
		r, err := lockUser(ctx, q, t, s)
		if err != nil {
			if errors.Is(err, ports.ErrNotFound) {
				return nil, ports.ErrInvalid
			}
			return nil, err
		}
		if !slices.Contains(out, r.ID) {
			out = append(out, r.ID)
		}
	}
	return out, nil
}

// CreateGroup creates a group of the token's issuer (F919).
func (s *Service) CreateGroup(ctx context.Context, pt ports.Token, in ports.GroupInput) (ports.Group, error) {
	var out ports.Group
	err := s.inDir(ctx, pt, func(ctx context.Context, tx db.TenantTx, q *dbq.Queries, t token) error {
		if err := s.entitledSCIM(ctx); err != nil { // the org's plan: ctx names the org
			return err
		}
		if attr(in.DisplayName, true) != nil || attr(in.ExternalID, false) != nil {
			return ports.ErrInvalid
		}
		add, err := members(ctx, q, t, in.Members)
		if err != nil {
			return err
		}
		n, err := q.CountDirectoryGroups(ctx, dbq.CountDirectoryGroupsParams{OrgID: t.org, Issuer: t.Issuer, DisplayName: &in.DisplayName})
		if err != nil {
			return err
		}
		if n > 0 {
			return ports.ErrConflict
		}
		g, err := q.InsertGroup(ctx, dbq.InsertGroupParams{
			OrgID: t.org, ID: ids.NewV7(), Issuer: t.Issuer, DisplayName: in.DisplayName, ExternalID: optional(in.ExternalID),
		})
		if db.IsUniqueViolation(err) {
			return ports.ErrConflict // a concurrent create of the same name
		} else if err != nil {
			return err
		}
		added, removed, err := s.setMembers(ctx, q, t, g.ID, add, nil)
		if err != nil {
			return err
		}
		if err := s.record(ctx, tx, t, auditkind.ScimGroupCreated, "group", g.ID, map[string]string{
			"members_added": strconv.Itoa(len(add)), "bindings_added": strconv.Itoa(added), "bindings_removed": strconv.Itoa(removed),
		}); err != nil {
			return err
		}
		out, err = s.groupOut(ctx, q, g)
		return err
	})
	return out, err
}

// ReplaceGroup sets a group's name, external id and members (PUT).
func (s *Service) ReplaceGroup(ctx context.Context, pt ports.Token, id string, in ports.GroupInput) (ports.Group, error) {
	return s.changeGroup(ctx, pt, id, &in, ports.GroupChange{DisplayName: &in.DisplayName, ExternalID: &in.ExternalID})
}

// ChangeGroup applies a partial change (PATCH). Removing members works in
// every edition. Below Enterprise a request that removes applies its
// removals only, records the parts it dropped and returns the stored
// group; one that does not remove is ErrEdition (D528).
func (s *Service) ChangeGroup(ctx context.Context, pt ports.Token, id string, c ports.GroupChange) (ports.Group, error) {
	return s.changeGroup(ctx, pt, id, nil, c)
}

func (s *Service) changeGroup(ctx context.Context, pt ports.Token, id string, replace *ports.GroupInput, c ports.GroupChange) (ports.Group, error) {
	var out ports.Group
	err := s.inDir(ctx, pt, func(ctx context.Context, tx db.TenantTx, q *dbq.Queries, t token) error {
		full, err := s.fullEdition(ctx)
		if err != nil {
			return err
		}
		g, err := lockGroup(ctx, q, t, id)
		if err != nil {
			return err
		}
		name, ext := g.DisplayName, deref(g.ExternalID)
		if c.DisplayName != nil {
			name = *c.DisplayName
		}
		if c.ExternalID != nil {
			ext = *c.ExternalID
		}
		if attr(name, true) != nil || attr(ext, false) != nil {
			return ports.ErrInvalid
		}
		add, remove, err := memberChange(ctx, q, t, g.ID, replace, c)
		if err != nil {
			return err
		}
		var parts []string
		if !full {
			if len(remove) == 0 {
				return ports.ErrEdition
			}
			if name != g.DisplayName {
				parts = append(parts, "displayName")
			}
			if ext != deref(g.ExternalID) {
				parts = append(parts, "externalId")
			}
			if len(add) > 0 {
				parts = append(parts, "members_added")
			}
			name, ext, add = g.DisplayName, deref(g.ExternalID), nil
		}
		if name != g.DisplayName {
			n, err := q.CountDirectoryGroups(ctx, dbq.CountDirectoryGroupsParams{OrgID: t.org, Issuer: t.Issuer, DisplayName: &name})
			if err != nil {
				return err
			}
			if n > 0 {
				return ports.ErrConflict
			}
		}
		if name != g.DisplayName || ext != deref(g.ExternalID) {
			g, err = q.SetGroup(ctx, dbq.SetGroupParams{DisplayName: name, ExternalID: optional(ext), OrgID: t.org, ID: g.ID})
			if db.IsUniqueViolation(err) {
				return ports.ErrConflict
			} else if err != nil {
				return err
			}
		}
		added, removed, err := s.setMembers(ctx, q, t, g.ID, add, remove)
		if err != nil {
			return err
		}
		if err := s.record(ctx, tx, t, auditkind.ScimGroupChanged, "group", g.ID, map[string]string{
			"members_added": strconv.Itoa(len(add)), "members_removed": strconv.Itoa(len(remove)),
			"bindings_added": strconv.Itoa(added), "bindings_removed": strconv.Itoa(removed),
		}); err != nil {
			return err
		}
		if err := s.dropped(ctx, tx, t, "group", g.ID, parts); err != nil {
			return err
		}
		out, err = s.groupOut(ctx, q, g)
		return err
	})
	return out, err
}

// memberChange is who a change adds and removes.
func memberChange(ctx context.Context, q *dbq.Queries, t token, group ids.UUID, replace *ports.GroupInput, c ports.GroupChange) (add, remove []ids.UUID, err error) {
	if replace != nil {
		want, err := members(ctx, q, t, replace.Members)
		if err != nil {
			return nil, nil, err
		}
		have, err := q.GroupMemberIDs(ctx, t.org, group)
		if err != nil {
			return nil, nil, err
		}
		for _, w := range want {
			if !slices.Contains(have, w) {
				add = append(add, w)
			}
		}
		for _, h := range have {
			if !slices.Contains(want, h) {
				remove = append(remove, h)
			}
		}
		return add, remove, nil
	}
	if add, err = members(ctx, q, t, c.AddMembers); err != nil {
		return nil, nil, err
	}
	for _, r := range c.RemoveUsers {
		if u, err := ids.ParseUUID(r); err == nil && !slices.Contains(remove, u) {
			remove = append(remove, u) // removing someone who is not a member is no error
		}
	}
	if len(remove) > MaxMembers {
		return nil, nil, ports.ErrInvalid
	}
	return add, remove, nil
}

// DeleteGroup deletes a group, its members and its role mappings; the
// bindings it gave go with it. Works in every edition.
func (s *Service) DeleteGroup(ctx context.Context, pt ports.Token, id string) error {
	return s.inDir(ctx, pt, func(ctx context.Context, tx db.TenantTx, q *dbq.Queries, t token) error {
		g, err := lockGroup(ctx, q, t, id)
		if err != nil {
			return err
		}
		have, err := q.GroupMemberIDs(ctx, t.org, g.ID)
		if err != nil {
			return err
		}
		if err := q.DeleteGroup(ctx, t.org, g.ID); err != nil {
			return err
		}
		removed := 0
		for _, u := range have {
			_, r, err := reconcile(ctx, q, t.org, u)
			if err != nil {
				return err
			}
			removed += r
		}
		return s.record(ctx, tx, t, auditkind.ScimGroupDeleted, "group", g.ID, map[string]string{
			"members_removed": strconv.Itoa(len(have)), "bindings_removed": strconv.Itoa(removed),
		})
	})
}

// setMembers adds and removes members, then re-derives the bindings of
// every user it touched, in the same transaction.
func (s *Service) setMembers(ctx context.Context, q *dbq.Queries, t token, group ids.UUID, add, remove []ids.UUID) (added, removed int, err error) {
	for _, u := range add {
		if err := q.AddGroupMember(ctx, t.org, group, u); err != nil {
			return 0, 0, err
		}
	}
	for _, u := range remove {
		if err := q.RemoveGroupMember(ctx, t.org, group, u); err != nil {
			return 0, 0, err
		}
	}
	for _, u := range append(slices.Clone(add), remove...) {
		a, r, err := reconcile(ctx, q, t.org, u)
		if err != nil {
			return 0, 0, err
		}
		added, removed = added+a, removed+r
	}
	return added, removed, nil
}

// bindingKey identifies a binding by what it grants.
type bindingKey struct {
	role, scope   string
	bu, team, env ids.UUID
}

func keyOf(role, scope string, bu, team, env *ids.UUID) bindingKey {
	k := bindingKey{role: role, scope: scope}
	if bu != nil {
		k.bu = *bu
	}
	if team != nil {
		k.team = *team
	}
	if env != nil {
		k.env = *env
	}
	return k
}

// reconcile makes a user's provisioned bindings what their groups' mappings
// give. It adds and removes only bindings a mapping made, never one a person
// made, and never a role that stays in PantherClaw, which the database
// refuses too (HR-630).
func reconcile(ctx context.Context, q *dbq.Queries, org ids.OrgID, user ids.UUID) (added, removed int, err error) {
	want, err := q.DesiredBindings(ctx, org, user)
	if err != nil {
		return 0, 0, err
	}
	have, err := q.ProvisionedBindings(ctx, org, &user)
	if err != nil {
		return 0, 0, err
	}
	wanted := map[bindingKey]bool{}
	for _, w := range want {
		if domain.CheckMappable(td.RoleName(w.Role), td.ScopeType(w.ScopeType)) != nil {
			continue // a mapping that can't be bound now gives nothing
		}
		wanted[keyOf(w.Role, w.ScopeType, w.BusinessUnitID, w.TeamID, w.EnvironmentID)] = true
	}
	had := map[bindingKey]bool{}
	for _, h := range have {
		k := keyOf(h.Role, h.ScopeType, h.BusinessUnitID, h.TeamID, h.EnvironmentID)
		had[k] = true
		if !wanted[k] {
			if err := q.DeleteProvisionedBinding(ctx, org, h.ID); err != nil {
				return 0, 0, err
			}
			removed++
		}
	}
	for _, w := range want {
		k := keyOf(w.Role, w.ScopeType, w.BusinessUnitID, w.TeamID, w.EnvironmentID)
		if !wanted[k] || had[k] {
			continue
		}
		had[k] = true
		n, err := q.InsertProvisionedBinding(ctx, dbq.InsertProvisionedBindingParams{
			OrgID: org, ID: ids.NewV7(), Role: w.Role, UserID: &user, ScopeType: w.ScopeType,
			BusinessUnitID: w.BusinessUnitID, TeamID: w.TeamID, EnvironmentID: w.EnvironmentID,
		})
		if err != nil {
			return 0, 0, err
		}
		added += int(n)
	}
	return added, removed, nil
}
