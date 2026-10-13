// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"strconv"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// M8 track G commands: the GitHub identity links independence compares
// (HR-207). A person links their own account by signing in to GitHub
// (pclaw github link, P2f); an identity manager can only unlink others, and
// registers the GitHub accounts that are not people (exemptions).

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
		"github identity unlink": rpc("github identity unlink ID (another person's link)", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.github.UnlinkIdentity(ctx, &pantherclawv1.UnlinkIdentityRequest{Id: a[0]})
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
		"github exemption add": rpc("github exemption add GITHUB_USER_ID LOGIN REASON (a bot or machine user, not a person)", 3,
			func(*flag.FlagSet) call {
				return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
					id, err := strconv.ParseInt(a[0], 10, 64)
					if err != nil {
						return nil, errUsage
					}
					return c.github.ExemptAccount(ctx, &pantherclawv1.ExemptAccountRequest{GithubUserId: id, GithubLogin: a[1], Reason: a[2]})
				}
			}),
		"github exemption remove": rpc("github exemption remove GITHUB_USER_ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				id, err := strconv.ParseInt(a[0], 10, 64)
				if err != nil {
					return nil, errUsage
				}
				return c.github.RemoveExemption(ctx, &pantherclawv1.RemoveExemptionRequest{GithubUserId: id})
			}
		}),
		"github exemption list": rpc("github exemption list", 0, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.github.ListExemptions(ctx, &pantherclawv1.ListExemptionsRequest{})
			}
		}),
	}
}
