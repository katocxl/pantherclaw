// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// M8 track G commands: the GitHub identity links independence compares
// (HR-207), and organization scans (HR-209).

func init() {
	for k, v := range m8gCommands() {
		commands[k] = v
	}
}

// m8gClients are the M8 track G service clients.
type m8gClients struct {
	github pantherclawv1connect.GitHubServiceClient
}

func m8gCommands() map[string]command {
	return map[string]command{
		"github identity link": rpc("github identity link --user ID --login LOGIN --github-id N", 0, func(fs *flag.FlagSet) call {
			user, login := fs.String("user", "", "the person"), fs.String("login", "", "their GitHub login")
			id := fs.Int64("github-id", 0, "their GitHub user id (GET https://api.github.com/users/LOGIN shows it)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.github.LinkIdentity(ctx, &pantherclawv1.LinkIdentityRequest{UserId: *user, GithubLogin: *login, GithubUserId: *id})
			}
		}),
		"github identity unlink": rpc("github identity unlink ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.github.UnlinkIdentity(ctx, &pantherclawv1.UnlinkIdentityRequest{Id: a[0]})
			}
		}),
		"github scan": rpc("github scan --connection ID", 0, func(fs *flag.FlagSet) call {
			conn := fs.String("connection", "", "the GitHub App connection whose organization to scan (Team edition)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.github.StartOrgScan(ctx, &pantherclawv1.StartOrgScanRequest{ConnectionId: *conn})
			}
		}),
		"github scan get": rpc("github scan get ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.github.GetOrgScan(ctx, &pantherclawv1.GetOrgScanRequest{Id: a[0]})
			}
		}),
		"github scan findings": rpc("github scan findings ID", 1, func(fs *flag.FlagSet) call {
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.github.ListOrgScanFindings(ctx, &pantherclawv1.ListOrgScanFindingsRequest{ScanId: a[0], PageSize: size(n), PageToken: *tok})
			}
		}),
		"github identity list": rpc("github identity list [--user ID]", 0, func(fs *flag.FlagSet) call {
			var user optional
			fs.Var(&user, "user", "only this person's")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				req := &pantherclawv1.ListIdentitiesRequest{PageSize: size(n), PageToken: *tok}
				if p := user.ptr(); p != nil {
					req.UserId = *p
				}
				return c.github.ListIdentities(ctx, req)
			}
		}),
	}
}
