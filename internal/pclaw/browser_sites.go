// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// `pclaw browser sites` (G0 M33 D976) reads and changes the org's browser
// site list. A browser action on a site not on the list holds for a
// person, and an empty list holds every site. Adding a site files a
// protected change: it applies only when a second person confirms it with
// a security key. Removing one applies at once.

func init() {
	commands["browser sites"] = group("browser sites", browserSiteCommands())
}

// siteCall is one BrowserService call.
type siteCall func(ctx context.Context, c pantherclawv1connect.BrowserServiceClient, args []string) (proto.Message, error)

// siteRPC builds a command on BrowserService with nargs positional
// arguments before any flags.
func siteRPC(usage string, nargs int, setup func(fs *flag.FlagSet) siteCall) command {
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
		s, err := a.session()
		if err != nil {
			return err
		}
		res, err := fn(ctx, pantherclawv1connect.NewBrowserServiceClient(s.connect()), args[:nargs])
		if err != nil {
			return err
		}
		if err := a.print(res); err != nil {
			return err
		}
		if r, ok := res.(*pantherclawv1.AddBrowserSiteResponse); ok {
			_, _ = fmt.Fprintf(a.stderr, "protected change %s filed: the site is added when a second person confirms it with a security key\n",
				r.GetProtectedChangeId())
		}
		return nil
	}}
}

func browserSiteCommands() map[string]command {
	return map[string]command{
		"list": siteRPC("browser sites list", 0, func(*flag.FlagSet) siteCall {
			return func(ctx context.Context, c pantherclawv1connect.BrowserServiceClient, _ []string) (proto.Message, error) {
				return c.ListBrowserSites(ctx, &pantherclawv1.ListBrowserSitesRequest{})
			}
		}),
		"add": siteRPC("browser sites add --host HOST [--subdomains] [--compare] [--selector CSS]... [--note TEXT] --reason TEXT", 0,
			func(fs *flag.FlagSet) siteCall {
				host := fs.String("host", "", "the site's host: a lower-case DNS name of at least two labels, no IP and no port")
				subdomains := fs.Bool("subdomains", false, "every name under the host matches too")
				compare := fs.Bool("compare", false, "the gateway's cloaking compare covers the site (alert only)")
				var selectors list
				fs.Var(&selectors, "selector", "a CSS selector of an element whose click is asked (repeatable, at most 16)")
				note := fs.String("note", "", "a note (at most 256 characters)")
				reason := fs.String("reason", "", "why the org lists this site (1 to 500 characters)")
				return func(ctx context.Context, c pantherclawv1connect.BrowserServiceClient, _ []string) (proto.Message, error) {
					return c.AddBrowserSite(ctx, &pantherclawv1.AddBrowserSiteRequest{
						Host: *host, IncludeSubdomains: *subdomains, Compare: *compare, ClickSelectors: selectors, Note: *note, Reason: *reason,
					})
				}
			}),
		"remove": siteRPC("browser sites remove ID --reason TEXT", 1, func(fs *flag.FlagSet) siteCall {
			reason := fs.String("reason", "", "why the site is removed (1 to 500 characters)")
			return func(ctx context.Context, c pantherclawv1connect.BrowserServiceClient, a []string) (proto.Message, error) {
				return c.RemoveBrowserSite(ctx, &pantherclawv1.RemoveBrowserSiteRequest{Id: a[0], Reason: *reason})
			}
		}),
	}
}
