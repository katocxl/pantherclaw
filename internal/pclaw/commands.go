// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// call is one RPC: it receives the positional arguments and returns the
// response to print.
type call func(ctx context.Context, c clients, args []string) (proto.Message, error)

// rpc builds a command with nargs positional arguments (before any flags);
// setup declares the flags and returns the call.
func rpc(usage string, nargs int, setup func(fs *flag.FlagSet) call) command {
	return command{usage: usage, run: func(ctx context.Context, a *app, args []string) error {
		if len(args) < nargs {
			return errUsage
		}
		fs := flag.NewFlagSet(usage, flag.ContinueOnError)
		fs.SetOutput(a.stderr)
		fn := setup(fs)
		if err := fs.Parse(args[nargs:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errUsage
		}
		c, err := a.clients()
		if err != nil {
			return err
		}
		res, err := fn(ctx, c, args[:nargs])
		if err != nil {
			return err
		}
		if err := a.print(res); err != nil {
			return err
		}
		a.decisionNotes(res)
		return nil
	}}
}

// print writes a response as indented JSON (field names as in the API).
func (a *app) print(m proto.Message) error {
	b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(m)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.stdout, string(b))
	return err
}

// list is a repeatable string flag.
type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

// optional is a string flag that records whether it was set (updates send
// only the fields that are set).
type optional struct {
	v   string
	set bool
}

func (o *optional) String() string     { return o.v }
func (o *optional) Set(v string) error { o.v, o.set = v, true; return nil }
func (o *optional) ptr() *string {
	if !o.set {
		return nil
	}
	return &o.v
}

func paging(fs *flag.FlagSet) (*int, *string) {
	return fs.Int("page-size", 0, "results per page (default 50, at most 200)"), fs.String("page-token", "", "next_page_token from a previous call")
}

func size(n *int) int32 { return int32(min(max(*n, 0), 200)) }

var envKinds = map[string]pantherclawv1.EnvironmentKind{
	"development": pantherclawv1.EnvironmentKind_ENVIRONMENT_KIND_DEVELOPMENT,
	"dev":         pantherclawv1.EnvironmentKind_ENVIRONMENT_KIND_DEVELOPMENT,
	"staging":     pantherclawv1.EnvironmentKind_ENVIRONMENT_KIND_STAGING,
	"production":  pantherclawv1.EnvironmentKind_ENVIRONMENT_KIND_PRODUCTION,
	"prod":        pantherclawv1.EnvironmentKind_ENVIRONMENT_KIND_PRODUCTION,
}

var scopeTypes = map[string]pantherclawv1.ScopeType{
	"org": pantherclawv1.ScopeType_SCOPE_TYPE_ORG, "bu": pantherclawv1.ScopeType_SCOPE_TYPE_BUSINESS_UNIT,
	"team": pantherclawv1.ScopeType_SCOPE_TYPE_TEAM, "env": pantherclawv1.ScopeType_SCOPE_TYPE_ENVIRONMENT,
}

func init() {
	for k, v := range tenancyCommands() {
		commands[k] = v
	}
	for k, v := range accessCommands() {
		commands[k] = v
	}
	for k, v := range serviceAccountCommands() {
		commands[k] = v
	}
	for _, group := range []map[string]command{agentCommands(), identityCommands(), workloadCommands()} {
		for k, v := range group {
			commands[k] = v
		}
	}
}

func tenancyCommands() map[string]command {
	return map[string]command{
		"org get": rpc("org get", 0, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.tenancy.GetOrg(ctx, &pantherclawv1.GetOrgRequest{})
			}
		}),
		"org update": rpc("org update --name NAME", 0, func(fs *flag.FlagSet) call {
			name := fs.String("name", "", "new name")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.tenancy.UpdateOrg(ctx, &pantherclawv1.UpdateOrgRequest{Name: *name})
			}
		}),
		"bu create": rpc("bu create --slug SLUG --name NAME [--description D]", 0, func(fs *flag.FlagSet) call {
			slug, name, desc := fs.String("slug", "", "identifier"), fs.String("name", "", "display name"), fs.String("description", "", "description")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.tenancy.CreateBusinessUnit(ctx, &pantherclawv1.CreateBusinessUnitRequest{Slug: *slug, Name: *name, Description: *desc})
			}
		}),
		"bu get": rpc("bu get ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.tenancy.GetBusinessUnit(ctx, &pantherclawv1.GetBusinessUnitRequest{Id: a[0]})
			}
		}),
		"bu list": rpc("bu list [--all]", 0, func(fs *flag.FlagSet) call {
			all := fs.Bool("all", false, "include archived")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.tenancy.ListBusinessUnits(ctx, &pantherclawv1.ListBusinessUnitsRequest{PageSize: size(n), PageToken: *tok, IncludeArchived: *all})
			}
		}),
		"bu update": rpc("bu update ID [--name N] [--description D]", 1, func(fs *flag.FlagSet) call {
			var name, desc optional
			fs.Var(&name, "name", "new name")
			fs.Var(&desc, "description", "new description")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.tenancy.UpdateBusinessUnit(ctx, &pantherclawv1.UpdateBusinessUnitRequest{Id: a[0], Name: name.ptr(), Description: desc.ptr()})
			}
		}),
		"bu archive": rpc("bu archive ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.tenancy.ArchiveBusinessUnit(ctx, &pantherclawv1.ArchiveBusinessUnitRequest{Id: a[0]})
			}
		}),
		"team create": rpc("team create --slug SLUG --name NAME [--bu ID] [--description D]", 0, func(fs *flag.FlagSet) call {
			slug, name, desc, bu := fs.String("slug", "", "identifier"), fs.String("name", "", "display name"),
				fs.String("description", "", "description"), fs.String("bu", "", "parent business unit")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.tenancy.CreateTeam(ctx, &pantherclawv1.CreateTeamRequest{BusinessUnitId: *bu, Slug: *slug, Name: *name, Description: *desc})
			}
		}),
		"team get": rpc("team get ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.tenancy.GetTeam(ctx, &pantherclawv1.GetTeamRequest{Id: a[0]})
			}
		}),
		"team list": rpc("team list [--bu ID] [--all]", 0, func(fs *flag.FlagSet) call {
			bu, all := fs.String("bu", "", "only this business unit"), fs.Bool("all", false, "include archived")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.tenancy.ListTeams(ctx, &pantherclawv1.ListTeamsRequest{PageSize: size(n), PageToken: *tok, BusinessUnitId: *bu, IncludeArchived: *all})
			}
		}),
		"team update": rpc("team update ID [--name N] [--description D]", 1, func(fs *flag.FlagSet) call {
			var name, desc optional
			fs.Var(&name, "name", "new name")
			fs.Var(&desc, "description", "new description")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.tenancy.UpdateTeam(ctx, &pantherclawv1.UpdateTeamRequest{Id: a[0], Name: name.ptr(), Description: desc.ptr()})
			}
		}),
		"team archive": rpc("team archive ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.tenancy.ArchiveTeam(ctx, &pantherclawv1.ArchiveTeamRequest{Id: a[0]})
			}
		}),
		"team members": rpc("team members TEAM", 1, func(fs *flag.FlagSet) call {
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.tenancy.ListTeamMembers(ctx, &pantherclawv1.ListTeamMembersRequest{TeamId: a[0], PageSize: size(n), PageToken: *tok})
			}
		}),
		"team add-member": rpc("team add-member TEAM USER", 2, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.tenancy.AddTeamMember(ctx, &pantherclawv1.AddTeamMemberRequest{TeamId: a[0], UserId: a[1]})
			}
		}),
		"team remove-member": rpc("team remove-member TEAM USER", 2, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.tenancy.RemoveTeamMember(ctx, &pantherclawv1.RemoveTeamMemberRequest{TeamId: a[0], UserId: a[1]})
			}
		}),
		"env create": rpc("env create --slug SLUG --name NAME --kind dev|staging|prod [--team ID] [--description D]", 0, func(fs *flag.FlagSet) call {
			slug, name, desc, team, kind := fs.String("slug", "", "identifier"), fs.String("name", "", "display name"),
				fs.String("description", "", "description"), fs.String("team", "", "owning team (default: the org)"),
				fs.String("kind", "", "development, staging or production")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				k, ok := envKinds[strings.ToLower(*kind)]
				if !ok {
					return nil, fmt.Errorf("--kind must be development, staging or production")
				}
				return c.tenancy.CreateEnvironment(ctx, &pantherclawv1.CreateEnvironmentRequest{
					TeamId: *team, Slug: *slug, Name: *name, Description: *desc, Kind: k,
				})
			}
		}),
		"env get": rpc("env get ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.tenancy.GetEnvironment(ctx, &pantherclawv1.GetEnvironmentRequest{Id: a[0]})
			}
		}),
		"env list": rpc("env list [--team ID] [--all]", 0, func(fs *flag.FlagSet) call {
			team, all := fs.String("team", "", "only this team"), fs.Bool("all", false, "include archived")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.tenancy.ListEnvironments(ctx, &pantherclawv1.ListEnvironmentsRequest{PageSize: size(n), PageToken: *tok, TeamId: *team, IncludeArchived: *all})
			}
		}),
		"env update": rpc("env update ID [--name N] [--description D]", 1, func(fs *flag.FlagSet) call {
			var name, desc optional
			fs.Var(&name, "name", "new name")
			fs.Var(&desc, "description", "new description")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.tenancy.UpdateEnvironment(ctx, &pantherclawv1.UpdateEnvironmentRequest{Id: a[0], Name: name.ptr(), Description: desc.ptr()})
			}
		}),
		"env archive": rpc("env archive ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.tenancy.ArchiveEnvironment(ctx, &pantherclawv1.ArchiveEnvironmentRequest{Id: a[0]})
			}
		}),
	}
}

func accessCommands() map[string]command {
	setState := func(state pantherclawv1.AccountState) func(*flag.FlagSet) call {
		return func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.access.SetUserState(ctx, &pantherclawv1.SetUserStateRequest{Id: a[0], State: state})
			}
		}
	}
	return map[string]command{
		"user list": rpc("user list", 0, func(fs *flag.FlagSet) call {
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.access.ListUsers(ctx, &pantherclawv1.ListUsersRequest{PageSize: size(n), PageToken: *tok})
			}
		}),
		"user get": rpc("user get ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.access.GetUser(ctx, &pantherclawv1.GetUserRequest{Id: a[0]})
			}
		}),
		"user disable": rpc("user disable ID", 1, setState(pantherclawv1.AccountState_ACCOUNT_STATE_DISABLED)),
		"user enable":  rpc("user enable ID", 1, setState(pantherclawv1.AccountState_ACCOUNT_STATE_ACTIVE)),
		"invite create": rpc("invite create --email E [--role R]... [--ttl-hours N]", 0, func(fs *flag.FlagSet) call {
			var roles list
			email, ttl := fs.String("email", "", "invitee email"), fs.Int("ttl-hours", 0, "validity (default 168, at most 720)")
			fs.Var(&roles, "role", "org-scope role to grant on acceptance (repeatable)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.access.CreateInvitation(ctx, &pantherclawv1.CreateInvitationRequest{
					Email: *email, Roles: roles, TtlHours: int32(min(max(*ttl, 0), 720)),
				})
			}
		}),
		"invite list": rpc("invite list [--all]", 0, func(fs *flag.FlagSet) call {
			all := fs.Bool("all", false, "include accepted, revoked and expired")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.access.ListInvitations(ctx, &pantherclawv1.ListInvitationsRequest{PageSize: size(n), PageToken: *tok, IncludeClosed: *all})
			}
		}),
		"invite revoke": rpc("invite revoke ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.access.RevokeInvitation(ctx, &pantherclawv1.RevokeInvitationRequest{Id: a[0]})
			}
		}),
		"role list": rpc("role list", 0, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.access.ListRoles(ctx, &pantherclawv1.ListRolesRequest{})
			}
		}),
		"role bindings": rpc("role bindings [--user ID | --sa ID]", 0, func(fs *flag.FlagSet) call {
			user, sa := fs.String("user", "", "only this user"), fs.String("sa", "", "only this service account")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				req := &pantherclawv1.ListRoleBindingsRequest{PageSize: size(n), PageToken: *tok}
				switch {
				case *user != "" && *sa != "":
					return nil, fmt.Errorf("use --user or --sa, not both")
				case *user != "":
					req.PrincipalType, req.PrincipalId = pantherclawv1.PrincipalType_PRINCIPAL_TYPE_USER, *user
				case *sa != "":
					req.PrincipalType, req.PrincipalId = pantherclawv1.PrincipalType_PRINCIPAL_TYPE_SERVICE_ACCOUNT, *sa
				}
				return c.access.ListRoleBindings(ctx, req)
			}
		}),
		"role bind": rpc("role bind --role R (--user ID | --sa ID) [--scope org|bu|team|env --scope-id ID]", 0, func(fs *flag.FlagSet) call {
			role, user, sa := fs.String("role", "", "role name (see pclaw role list)"), fs.String("user", "", "user id"), fs.String("sa", "", "service account id")
			scope, scopeID := fs.String("scope", "org", "org, bu, team or env"), fs.String("scope-id", "", "id of the business unit, team or environment")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				st, ok := scopeTypes[*scope]
				if !ok {
					return nil, fmt.Errorf("--scope must be org, bu, team or env")
				}
				req := &pantherclawv1.CreateRoleBindingRequest{Role: *role, Scope: &pantherclawv1.Scope{Type: st, Id: *scopeID}}
				switch {
				case (*user == "") == (*sa == ""):
					return nil, fmt.Errorf("give exactly one of --user and --sa")
				case *user != "":
					req.PrincipalType, req.PrincipalId = pantherclawv1.PrincipalType_PRINCIPAL_TYPE_USER, *user
				default:
					req.PrincipalType, req.PrincipalId = pantherclawv1.PrincipalType_PRINCIPAL_TYPE_SERVICE_ACCOUNT, *sa
				}
				return c.access.CreateRoleBinding(ctx, req)
			}
		}),
		"role unbind": rpc("role unbind BINDING", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.access.DeleteRoleBinding(ctx, &pantherclawv1.DeleteRoleBindingRequest{Id: a[0]})
			}
		}),
	}
}
