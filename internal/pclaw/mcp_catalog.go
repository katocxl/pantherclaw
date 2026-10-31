// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// `pclaw mcp catalog` (G0 M24 D225; F878) reads and changes the org's approved
// MCP server catalogue. Changing the mode and revoking need a person with a
// security-key step-up on a browser session, so here they answer
// STEP_UP_REQUIRED with a hint; their previews work. `export` writes a static
// file from the approved servers and opens no endpoint.

var (
	catalogModes = map[string]pb.McpCatalogMode{
		"off": pb.McpCatalogMode_MCP_CATALOG_MODE_OFF, "watch": pb.McpCatalogMode_MCP_CATALOG_MODE_WATCH,
		"enforce": pb.McpCatalogMode_MCP_CATALOG_MODE_ENFORCE,
	}
	catalogTransports = map[string]pb.McpServerTransport{
		"http": pb.McpServerTransport_MCP_SERVER_TRANSPORT_HTTP, "stdio": pb.McpServerTransport_MCP_SERVER_TRANSPORT_STDIO,
		"container": pb.McpServerTransport_MCP_SERVER_TRANSPORT_CONTAINER,
	}
	catalogStatuses = map[string]pb.McpServerStatus{
		"proposed": pb.McpServerStatus_MCP_SERVER_STATUS_PROPOSED, "approved": pb.McpServerStatus_MCP_SERVER_STATUS_APPROVED,
		"denied": pb.McpServerStatus_MCP_SERVER_STATUS_DENIED, "revoked": pb.McpServerStatus_MCP_SERVER_STATUS_REVOKED,
	}
)

// catalogCall is one call of a catalogue command.
type catalogCall func(ctx context.Context, c pantherclawv1connect.McpCatalogServiceClient, args []string) (proto.Message, error)

// catalogRPC is rpc for the catalogue's own client.
func catalogRPC(usage string, nargs int, setup func(fs *flag.FlagSet) catalogCall) command {
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
		c, err := a.catalogClient()
		if err != nil {
			return err
		}
		res, err := fn(ctx, c, args[:nargs])
		if err != nil {
			if strings.Contains(err.Error(), "STEP_UP_REQUIRED") {
				_, _ = fmt.Fprintln(a.stderr, "this needs a security-key step-up on a browser session; a CLI token cannot do it")
			}
			return err
		}
		return a.print(res)
	}}
}

func (a *app) catalogClient() (pantherclawv1connect.McpCatalogServiceClient, error) {
	s, err := a.session()
	if err != nil {
		return nil, err
	}
	return pantherclawv1connect.NewMcpCatalogServiceClient(s.connect()), nil
}

func catalogDigest(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("--digest: the preview_digest a preview printed")
	}
	return b, nil
}

func init() {
	commands["mcp catalog list"] = catalogRPC("mcp catalog list [--status proposed|approved|denied|revoked ...]", 0, func(fs *flag.FlagSet) catalogCall {
		var statuses list
		fs.Var(&statuses, "status", "only this status (repeatable)")
		n, tok := paging(fs)
		return func(ctx context.Context, c pantherclawv1connect.McpCatalogServiceClient, _ []string) (proto.Message, error) {
			req := &pb.ListServersRequest{PageSize: size(n), PageToken: *tok}
			for _, s := range statuses {
				v, err := enumFlag(catalogStatuses, "status", s)
				if err != nil {
					return nil, err
				}
				req.Statuses = append(req.Statuses, v)
			}
			return c.ListServers(ctx, req)
		}
	})
	commands["mcp catalog propose"] = catalogRPC("mcp catalog propose NAME --title T --transport http|stdio|container "+
		"[--url-host HOST [--url-path-prefix PATH]] [--image-digest sha256:HEX] [--package-ref REF] [--notes TEXT]", 1,
		func(fs *flag.FlagSet) catalogCall {
			title, transport := fs.String("title", "", "a readable name"), fs.String("transport", "", "http, stdio or container")
			host, prefix := fs.String("url-host", "", "the exact URL host"), fs.String("url-path-prefix", "", "whole path segments under the host")
			image, ref := fs.String("image-digest", "", "the exact image digest"), fs.String("package-ref", "", "the exact package reference")
			notes := fs.String("notes", "", "why it is proposed")
			return func(ctx context.Context, c pantherclawv1connect.McpCatalogServiceClient, a []string) (proto.Message, error) {
				t, err := enumFlag(catalogTransports, "transport", *transport)
				if err != nil {
					return nil, err
				}
				return c.ProposeServer(ctx, &pb.ProposeServerRequest{
					Name: a[0], Title: *title, Transport: t, UrlHost: *host, UrlPathPrefix: *prefix, ImageDigest: *image, PackageRef: *ref, Notes: *notes,
				})
			}
		})
	commands["mcp catalog approve"] = catalogRPC("mcp catalog approve ID", 1, func(*flag.FlagSet) catalogCall {
		return func(ctx context.Context, c pantherclawv1connect.McpCatalogServiceClient, a []string) (proto.Message, error) {
			return c.ApproveServer(ctx, &pb.ApproveServerRequest{Id: a[0]})
		}
	})
	commands["mcp catalog deny"] = catalogRPC("mcp catalog deny ID", 1, func(*flag.FlagSet) catalogCall {
		return func(ctx context.Context, c pantherclawv1connect.McpCatalogServiceClient, a []string) (proto.Message, error) {
			return c.DenyServer(ctx, &pb.DenyServerRequest{Id: a[0]})
		}
	})
	commands["mcp catalog mode"] = catalogRPC("mcp catalog mode show|off|watch|enforce [--preview] [--digest D --reason TEXT] "+
		"(changing it needs a security-key step-up on a browser session)", 1, func(fs *flag.FlagSet) catalogCall {
		preview := fs.Bool("preview", false, "say what the switch would do and print its digest")
		digest, reason := fs.String("digest", "", "the digest a preview printed, for enforce"), fs.String("reason", "", "why")
		return func(ctx context.Context, c pantherclawv1connect.McpCatalogServiceClient, a []string) (proto.Message, error) {
			if a[0] == "show" {
				return c.GetCatalogSettings(ctx, &pb.GetCatalogSettingsRequest{})
			}
			m, ok := catalogModes[a[0]]
			if !ok {
				return nil, errors.New("the mode is show, off, watch or enforce")
			}
			if *preview {
				return c.PreviewCatalogMode(ctx, &pb.PreviewCatalogModeRequest{Mode: m})
			}
			d, err := catalogDigest(*digest)
			if err != nil {
				return nil, err
			}
			return c.SetCatalogMode(ctx, &pb.SetCatalogModeRequest{Mode: m, PreviewDigest: d, Reason: *reason})
		}
	})
	commands["mcp catalog revoke"] = catalogRPC("mcp catalog revoke ID --preview | --digest D --reason TEXT "+
		"(revoking needs a security-key step-up on a browser session)", 1, func(fs *flag.FlagSet) catalogCall {
		preview := fs.Bool("preview", false, "say what a revoke would do and print its digest")
		digest, reason := fs.String("digest", "", "the digest a preview printed"), fs.String("reason", "", "why")
		return func(ctx context.Context, c pantherclawv1connect.McpCatalogServiceClient, a []string) (proto.Message, error) {
			if *preview {
				return c.PreviewServerRevoke(ctx, &pb.PreviewServerRevokeRequest{Id: a[0]})
			}
			d, err := catalogDigest(*digest)
			if err != nil {
				return nil, err
			}
			return c.RevokeServer(ctx, &pb.RevokeServerRequest{Id: a[0], PreviewDigest: d, Reason: *reason})
		}
	})
	commands["mcp catalog export"] = command{usage: "mcp catalog export --format managed-allow|registry-v0 [--out FILE]", run: catalogExport}
}

// catalogExport writes the approved servers as a static file (D225): the
// allow file `pclaw managed-settings generate --allow-file` reads, or a file
// in the official registry's shape. It serves nothing.
func catalogExport(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("mcp catalog export", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	format := fs.String("format", "", "managed-allow or registry-v0")
	out := fs.String("out", "", "write here instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*format != "managed-allow" && *format != "registry-v0") {
		return errUsage
	}
	c, err := a.catalogClient()
	if err != nil {
		return err
	}
	var servers []*pb.McpServer
	for tok := ""; ; {
		res, err := c.ListServers(ctx, &pb.ListServersRequest{
			PageSize: 200, PageToken: tok, Statuses: []pb.McpServerStatus{pb.McpServerStatus_MCP_SERVER_STATUS_APPROVED},
		})
		if err != nil {
			return err
		}
		servers = append(servers, res.GetServers()...)
		if tok = res.GetNextPageToken(); tok == "" {
			break
		}
	}
	doc := registryV0(servers)
	if *format == "managed-allow" {
		var left map[string]string
		doc, left = managedAllow(servers)
		for _, name := range slices.Sorted(maps.Keys(left)) {
			_, _ = fmt.Fprintln(a.stderr, "left out "+name+": "+left[name])
		}
	}
	b, err := json.Marshal(doc, json.Deterministic(true))
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if *out != "" {
		return os.WriteFile(*out, b, 0o644) //nolint:gosec // G306: a list of server names, meant to be shared
	}
	_, err = a.stdout.Write(b)
	return err
}

func serverURL(s *pb.McpServer) string {
	if s.GetUrlHost() == "" {
		return ""
	}
	return "https://" + s.GetUrlHost() + s.GetUrlPathPrefix()
}

// allowName is what the allow file takes as a name (Claude Code's allow list).
var allowName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// exactURL reports whether s is an address the allow file takes: no wildcard,
// credentials, query or fragment (D138).
func exactURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Host != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.Contains(s, "*")
}

// managedAllow is the allow file of G0 M23 D113, and the servers it left out,
// each with why. An entry has one matcher, its URL or else its command as a
// list. An entry with only a name would allow more than was approved (D225a),
// and one the file's reader refuses would lose the whole file, so neither is
// written (D138).
func managedAllow(servers []*pb.McpServer) (any, map[string]string) {
	type entry struct {
		Name    string   `json:"name"`
		URL     string   `json:"url,omitzero"`
		Command []string `json:"command,omitzero"`
	}
	out := make([]entry, 0, len(servers))
	left := map[string]string{}
	for _, s := range servers {
		e := entry{Name: s.GetName(), URL: serverURL(s)}
		switch {
		case !allowName.MatchString(e.Name):
			left[e.Name] = "the allow file takes 1 to 64 letters, digits, hyphens or underscores as a name"
			continue
		case e.URL != "" && !exactURL(e.URL):
			left[e.Name] = "the allow file takes an exact URL, with no wildcard, credentials or query"
			continue
		case e.URL == "" && s.GetPackageRef() == "":
			left[e.Name] = "the allow file cannot name a server by its image alone"
			continue
		case e.URL == "":
			e.Command = []string{s.GetPackageRef()}
		}
		out = append(out, e)
	}
	return map[string]any{"servers": out}, left
}

// Limits of the registry's server.json (name, description, title).
const (
	registryNamespace = "catalog.local/"
	registryTextMax   = 100
)

func clip(s string) string {
	if r := []rune(s); len(r) > registryTextMax {
		return string(r[:registryTextMax])
	}
	return s
}

// registryV0 is a static file in the shape of the official MCP registry's
// server list, checked against its published server.json schema (D225a): a
// name is namespace/name, so the catalogue's names sit under a namespace of
// their own; a description and title stop at 100 characters. The catalogue
// does not version its entries, so each server carries one fixed version.
func registryV0(servers []*pb.McpServer) any {
	type remote struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	type transport struct {
		Type string `json:"type"`
	}
	type pack struct {
		RegistryType string    `json:"registryType"`
		Identifier   string    `json:"identifier"`
		Transport    transport `json:"transport"`
	}
	type server struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Title       string   `json:"title"`
		Version     string   `json:"version"`
		Remotes     []remote `json:"remotes,omitzero"`
		Packages    []pack   `json:"packages,omitzero"`
	}
	type entry struct {
		Server server `json:"server"`
	}
	stdio := transport{Type: "stdio"}
	out := make([]entry, 0, len(servers))
	for _, s := range servers {
		text := clip(s.GetTitle())
		e := server{Name: registryNamespace + s.GetName(), Description: text, Title: text, Version: "1.0.0"}
		if u := serverURL(s); u != "" {
			e.Remotes = append(e.Remotes, remote{Type: "streamable-http", URL: u})
		}
		if r := s.GetPackageRef(); r != "" {
			e.Packages = append(e.Packages, pack{RegistryType: registryType(r), Identifier: r, Transport: stdio})
		}
		if d := s.GetImageDigest(); d != "" {
			e.Packages = append(e.Packages, pack{RegistryType: "oci", Identifier: d, Transport: stdio})
		}
		out = append(out, entry{Server: e})
	}
	return map[string]any{"servers": out, "metadata": map[string]any{"count": len(out)}}
}

func registryType(ref string) string {
	if strings.HasPrefix(ref, "@") || !strings.Contains(ref, "/") {
		return "npm"
	}
	return "oci"
}
