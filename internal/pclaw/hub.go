// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/hub"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	pcrpc "github.com/katocxl/pantherclaw/internal/platform/rpc"
)

// pclaw hub (G0 M23 D106, D107): the machine side of PantherClaw Hub. The
// server never fetches an index, so this is where one is fetched, verified
// and compared with what is installed; the server verifies everything again.

// defaultHubSource is the one place the Hub's address lives.
const defaultHubSource = "https://raw.githubusercontent.com/katocxl/pantherclaw/hub-index/"

// envHubDevKey names the public JWKS of the development Hub key. It is
// honored for a directory or loopback source only (D101).
const envHubDevKey = "PANTHERCLAW_HUB_DEV_KEY"

// defaultScenarioDir is a directory of customer-authored scenarios alone:
// `pclaw redteam run` refuses one that mixes them with RT files (D132).
const defaultScenarioDir = "./pantherclaw-scenarios"

const hubMaxRedirects = 5

func init() { maps.Copy(commands, hubCommands()) }

func hubCommands() map[string]command {
	return map[string]command{
		"hub search":  {"hub search [QUERY] [--kind KIND] [--source URL|DIR]", hubSearch},
		"hub show":    {"hub show NAME[@VERSION] [--source URL|DIR]", hubShow},
		"hub install": {"hub install NAME[@VERSION] [--set K=V]... [--dry-run] [--scenario-dir DIR] [--source URL|DIR]", hubInstall},
		"hub update":  {"hub update [--source URL|DIR]", hubUpdate},
		"hub status":  {"hub status", hubStatus},
	}
}

// hubSource is where an index and its items come from.
type hubSource struct {
	dir   string
	base  *url.URL
	hc    *http.Client
	local bool // a directory or loopback: the development key may apply
}

func (a *app) hubSource(raw string) (*hubSource, error) {
	if raw == "" {
		raw = defaultHubSource
	}
	if !strings.Contains(raw, "://") {
		return &hubSource{dir: raw, local: true}, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("hub: source: %w", err)
	}
	loop := hubLoopback(u.Hostname())
	if u.Scheme != "https" && (u.Scheme != "http" || !loop) {
		return nil, errors.New("hub: a source must use https (http only on loopback)")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("hub: a source is a plain URL with a host")
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/"
	hc := *a.http
	hc.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= hubMaxRedirects {
			return errors.New("hub: too many redirects")
		}
		if r.URL.Scheme != u.Scheme || r.URL.Host != u.Host {
			return fmt.Errorf("hub: refusing a redirect to another host (%s)", r.URL.Host)
		}
		return nil
	}
	return &hubSource{base: u, hc: &hc, local: loop}, nil
}

// read returns one file of the source, refusing more than maxBytes.
func (s *hubSource) read(ctx context.Context, rel string, maxBytes int64) ([]byte, error) {
	var r io.Reader
	if s.base == nil {
		f, err := os.Open(filepath.Join(s.dir, filepath.FromSlash(rel)))
		if err != nil {
			return nil, fmt.Errorf("hub: %w", err)
		}
		defer func() { _ = f.Close() }()
		r = f
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base.JoinPath(rel).String(), nil)
		if err != nil {
			return nil, err
		}
		res, err := s.hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("hub: fetch %s: %w", rel, err)
		}
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("hub: fetch %s: %s", rel, res.Status)
		}
		r = res.Body
	}
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("hub: read %s: %w", rel, err)
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("hub: %s is larger than %d bytes", rel, maxBytes)
	}
	return b, nil
}

// hubDir is where pclaw keeps its anti-rollback state and cache.
func hubDir(env Env) (string, error) {
	p, err := credsPath(env)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(p), "hub"), nil
}

// hubSeen is the last index this machine accepted from one signer.
type hubSeen struct {
	Version   uint64 `json:"version"`
	Digest    string `json:"digest"`
	ExpiresAt string `json:"expires_at"`
}

// hubLocal is state.json. Its indexes are keyed by signer, not by source: a
// mirror does not get a fresh start, and a development index does not raise
// the version the real Hub must beat.
type hubLocal struct {
	Current string             `json:"current"`
	Indexes map[string]hubSeen `json:"indexes"`
}

func hubStateKey(kid string) string {
	if domain.IsDevKID(kid) {
		return kid
	}
	return "hub"
}

func loadHubLocal(dir string) (hubLocal, error) {
	st := hubLocal{Indexes: map[string]hubSeen{}}
	b, err := os.ReadFile(filepath.Join(dir, "state.json")) //nolint:gosec // G304: pclaw's own state file
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		// Never treated as empty: that would reset the rollback check.
		return st, fmt.Errorf("hub: %s: %w", filepath.Join(dir, "state.json"), err)
	}
	if st.Indexes == nil {
		st.Indexes = map[string]hubSeen{}
	}
	return st, nil
}

// writeHubFile replaces path whole, so a crash leaves the old file.
func writeHubFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hub-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// hubIndex is a verified index and where its items come from.
type hubIndex struct {
	v    domain.Verified
	doc  string
	src  *hubSource
	dir  string
	warn io.Writer
}

// hubRoots returns the embedded roots and, for a local source, the
// development key.
func (a *app) hubRoots(local bool) (domain.Roots, error) {
	roots, err := hub.EmbeddedRoots()
	if err != nil {
		return nil, err
	}
	file, ok := a.env(envHubDevKey)
	if !ok || file == "" {
		return roots, nil
	}
	if !local {
		_, _ = fmt.Fprintf(a.stderr, "hub: %s is ignored: this source is not a directory or loopback\n", envHubDevKey)
		return roots, nil
	}
	b, err := os.ReadFile(file) //nolint:gosec // G304: the operator's own key file
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envHubDevKey, err)
	}
	dev, err := domain.ParseDevKey(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envHubDevKey, err)
	}
	all := domain.Roots{}
	maps.Copy(all, roots)
	maps.Copy(all, dev)
	return all, nil
}

// hubLoad fetches and verifies the index, refuses a rollback (HR-562) and
// records what it accepted.
func (a *app) hubLoad(ctx context.Context, source string) (*hubIndex, error) {
	src, err := a.hubSource(source)
	if err != nil {
		return nil, err
	}
	roots, err := a.hubRoots(src.local)
	if err != nil {
		return nil, err
	}
	// One more byte for the newline `pclaw-admin hub build` ends the file with.
	doc, err := src.read(ctx, "index.jws", domain.MaxIndexBytes+1)
	if err != nil {
		return nil, err
	}
	doc = bytes.TrimSpace(doc)
	v, err := domain.Verify(string(doc), roots, time.Now())
	if err != nil {
		return nil, hubCode(err)
	}
	dir, err := hubDir(a.env)
	if err != nil {
		return nil, err
	}
	local, err := loadHubLocal(dir)
	if err != nil {
		return nil, err
	}
	key := hubStateKey(v.KID)
	var last *domain.State
	if seen, ok := local.Indexes[key]; ok {
		last = &domain.State{Version: seen.Version, Digest: seen.Digest}
	}
	if err := domain.CheckAdvance(last, v); err != nil {
		return nil, hubCode(err)
	}
	local.Current = key
	local.Indexes[key] = hubSeen{Version: v.Version, Digest: v.Digest, ExpiresAt: v.ExpiresAt}
	b, err := json.Marshal(local, jsontext.Multiline(true))
	if err != nil {
		return nil, err
	}
	if err := writeHubFile(filepath.Join(dir, "cache", key+".jws"), doc); err != nil {
		return nil, err
	}
	if err := writeHubFile(filepath.Join(dir, "state.json"), b); err != nil {
		return nil, err
	}
	return &hubIndex{v: v, doc: string(doc), src: src, dir: dir, warn: a.stderr}, nil
}

// hubCode puts the stable code of a verification error in front of it, the
// code the server answers with (D105).
func hubCode(err error) error {
	for _, m := range []struct {
		sentinel error
		code     string
	}{
		{domain.ErrNoRoot, "HUB_NO_ROOT"},
		{domain.ErrExpired, "HUB_EXPIRED"},
		{domain.ErrRollback, "HUB_ROLLBACK"},
		{domain.ErrSignature, "HUB_SIGNATURE"},
		{domain.ErrDigest, "HUB_DIGEST"},
		{domain.ErrItem, "HUB_ITEM_INVALID"},
	} {
		if errors.Is(err, m.sentinel) {
			return fmt.Errorf("%s: %w", m.code, err)
		}
	}
	return err
}

// hubNewer reports whether version a is above b; both are MAJOR.MINOR.PATCH.
func hubNewer(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := range min(len(pa), len(pb)) {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x > y
		}
	}
	return false
}

// latest returns the highest version of each name.
func (x *hubIndex) latest() map[string]domain.Entry {
	out := map[string]domain.Entry{}
	for _, e := range x.v.Items {
		if have, ok := out[e.Name]; !ok || hubNewer(e.Version, have.Version) {
			out[e.Name] = e
		}
	}
	return out
}

// find resolves NAME or NAME@VERSION.
func (x *hubIndex) find(spec string) (domain.Entry, error) {
	name, version, exact := strings.Cut(spec, "@")
	if !exact {
		if e, ok := x.latest()[name]; ok {
			return e, nil
		}
	}
	for _, e := range x.v.Items {
		if e.Name == name && e.Version == version {
			return e, nil
		}
	}
	return domain.Entry{}, fmt.Errorf("hub: %s is not in index version %d", spec, x.v.Version)
}

// item returns the entry's exact bytes and decodes them. Cached and fetched
// bytes alike are matched to the signed digest before they are used.
func (x *hubIndex) item(ctx context.Context, want domain.Entry) ([]byte, domain.Item, error) {
	cached := filepath.Join(x.dir, "cache", "items", want.SHA256+".json")
	raw, err := os.ReadFile(cached) //nolint:gosec // G304: the name is a signed hex digest under pclaw's own directory
	if err != nil || domain.Digest(raw) != want.SHA256 {
		if raw, err = x.src.read(ctx, "items/"+want.SHA256+".json", domain.MaxItemBytes); err != nil {
			return nil, domain.Item{}, err
		}
	}
	e, it, err := x.v.Match(raw)
	if err != nil {
		return nil, domain.Item{}, hubCode(err)
	}
	if e.SHA256 != want.SHA256 {
		return nil, domain.Item{}, hubCode(fmt.Errorf("%w: not the item asked for", domain.ErrDigest))
	}
	if err := writeHubFile(cached, raw); err != nil {
		_, _ = fmt.Fprintln(x.warn, "hub: item not cached:", err)
	}
	return raw, it, nil
}

func hubFlags(fs *flag.FlagSet) *string {
	return fs.String("source", "", "Hub URL or local directory")
}

func hubSearch(ctx context.Context, a *app, args []string) error {
	var query string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		query, args = strings.ToLower(args[0]), args[1:]
	}
	fs := flag.NewFlagSet("hub search", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	source, kind := hubFlags(fs), fs.String("kind", "", "only this kind")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errUsage
	}
	if *kind != "" && !domain.Kind(*kind).Valid() {
		return fmt.Errorf("hub: unknown kind %q (one of %v)", *kind, domain.Kinds())
	}
	x, err := a.hubLoad(ctx, *source)
	if err != nil {
		return err
	}
	for _, e := range x.v.Items {
		text := strings.ToLower(e.Name + " " + e.Title + " " + e.Summary)
		if (*kind != "" && string(e.Kind) != *kind) || !strings.Contains(text, query) {
			continue
		}
		if _, err := fmt.Fprintf(a.stdout, "%s@%s\t%s\t%s\n", e.Name, e.Version, e.Kind, e.Title); err != nil {
			return err
		}
	}
	return nil
}

func hubShow(ctx context.Context, a *app, args []string) error {
	if len(args) < 1 {
		return errUsage
	}
	fs := flag.NewFlagSet("hub show", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	source := hubFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errUsage
	}
	x, err := a.hubLoad(ctx, *source)
	if err != nil {
		return err
	}
	e, err := x.find(args[0])
	if err != nil {
		return err
	}
	raw, _, err := x.item(ctx, e)
	if err != nil {
		return err
	}
	b, err := json.Marshal(struct {
		Entry domain.Entry   `json:"entry"`
		Item  jsontext.Value `json:"item"`
	}{e, jsontext.Value(raw)}, jsontext.Multiline(true))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.stdout, string(b))
	return err
}

func hubParams(sets []string) (map[string]string, error) {
	params := map[string]string{}
	for _, s := range sets {
		k, v, ok := strings.Cut(s, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("hub: --set %q: want K=V", s)
		}
		if _, dup := params[k]; dup {
			return nil, fmt.Errorf("hub: --set %s given twice", k)
		}
		params[k] = v
	}
	return params, nil
}

func hubInstall(ctx context.Context, a *app, args []string) error {
	if len(args) < 1 {
		return errUsage
	}
	fs := flag.NewFlagSet("hub install", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	source := hubFlags(fs)
	var sets list
	fs.Var(&sets, "set", "a template parameter, K=V (repeat)")
	dry := fs.Bool("dry-run", false, "verify and say what would happen; change nothing")
	scenarios := fs.String("scenario-dir", defaultScenarioDir, "where a range scenario is written")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errUsage
	}
	params, err := hubParams(sets)
	if err != nil {
		return err
	}
	x, err := a.hubLoad(ctx, *source)
	if err != nil {
		return err
	}
	e, err := x.find(args[0])
	if err != nil {
		return err
	}
	raw, it, err := x.item(ctx, e)
	if err != nil {
		return err
	}
	body, err := it.DecodeBody()
	if err != nil {
		return hubCode(err)
	}
	if b, ok := body.(domain.RangeScenarioBody); ok {
		return a.hubWriteScenario(b, *scenarios, *dry)
	}
	// The whole request travels in one RPC, whose size is capped.
	req := &pantherclawv1.InstallHubItemRequest{IndexJws: x.doc, Item: raw, Params: params}
	if n := proto.Size(req); n > pcrpc.MaxRequestBytes {
		return fmt.Errorf("hub: this install request is %d bytes; one request takes at most %d", n, pcrpc.MaxRequestBytes)
	}
	if *dry {
		_, err := fmt.Fprintf(a.stdout, "%s@%s (%s) verifies against index version %d; it would be installed as an inert draft.\n", e.Name, e.Version, e.Kind, x.v.Version)
		return err
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	res, err := hubClient(s).InstallHubItem(ctx, req)
	if err != nil {
		return err
	}
	return a.print(res)
}

func hubClient(s *session) pantherclawv1connect.HubServiceClient {
	return pantherclawv1connect.NewHubServiceClient(s.connect())
}

// hubWriteScenario writes a range scenario: no server installs one (D104).
// An existing file with other content is left alone.
func (a *app) hubWriteScenario(b domain.RangeScenarioBody, dir string, dry bool) error {
	path := filepath.Join(dir, b.FileName)
	have, err := os.ReadFile(path) //nolint:gosec // G304: the name passed domain.ValidScenarioFile
	switch {
	case err == nil && bytes.Equal(have, []byte(b.Scenario)):
		_, err := fmt.Fprintln(a.stdout, path, "is already there")
		return err
	case err == nil:
		return fmt.Errorf("hub: %s exists with other content", path)
	case !errors.Is(err, os.ErrNotExist):
		return err
	case dry:
		_, err := fmt.Fprintln(a.stdout, "would write", path)
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(b.Scenario), 0o600); err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.stdout, "wrote", path)
	return err
}

// hubInstalled lists the org's finished installs, every page.
func hubInstalled(ctx context.Context, c pantherclawv1connect.HubServiceClient) ([]*pantherclawv1.HubInstall, error) {
	var all []*pantherclawv1.HubInstall
	var tok string
	for {
		res, err := c.ListHubInstalls(ctx, &pantherclawv1.ListHubInstallsRequest{PageSize: 200, PageToken: tok})
		if err != nil {
			return nil, err
		}
		for _, in := range res.GetInstalls() {
			if in.GetStatus() == pantherclawv1.HubInstallStatus_HUB_INSTALL_STATUS_INSTALLED {
				all = append(all, in)
			}
		}
		if tok = res.GetNextPageToken(); tok == "" {
			return all, nil
		}
	}
}

// printHubUpdates says which installed items the index has a newer version
// of. The server has no such notion: it never reads an index (D107).
func (a *app) printHubUpdates(x *hubIndex, installed []*pantherclawv1.HubInstall) error {
	best := map[string]string{}
	for _, in := range installed {
		if v, ok := best[in.GetName()]; !ok || hubNewer(in.GetVersion(), v) {
			best[in.GetName()] = in.GetVersion()
		}
	}
	latest := x.latest()
	names := slices.Sorted(maps.Keys(best))
	var n int
	for _, name := range names {
		e, ok := latest[name]
		if !ok || !hubNewer(e.Version, best[name]) {
			continue
		}
		n++
		if _, err := fmt.Fprintf(a.stdout, "update available: %s %s -> %s (pclaw hub install %s)\n", name, best[name], e.Version, name); err != nil {
			return err
		}
	}
	if n == 0 {
		_, err := fmt.Fprintln(a.stdout, "every installed item is current")
		return err
	}
	return nil
}

func hubUpdate(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("hub update", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	source := hubFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errUsage
	}
	x, err := a.hubLoad(ctx, *source)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(a.stdout, "index version %d, %d items, expires %s\n", x.v.Version, len(x.v.Items), x.v.ExpiresAt); err != nil {
		return err
	}
	s, err := a.session()
	if errors.Is(err, ErrNotLoggedIn) {
		_, err := fmt.Fprintln(a.stdout, "not logged in: installed items were not compared")
		return err
	}
	if err != nil {
		return err
	}
	installed, err := hubInstalled(ctx, hubClient(s))
	if err != nil {
		return err
	}
	return a.printHubUpdates(x, installed)
}

// hubCached is the last index accepted here, verified again; nil when there
// is none or it no longer verifies.
func (a *app) hubCached(dir string, local hubLocal) *hubIndex {
	if local.Current == "" {
		return nil
	}
	doc, err := os.ReadFile(filepath.Join(dir, "cache", local.Current+".jws")) //nolint:gosec // G304: pclaw's own cache
	if err != nil {
		return nil
	}
	roots, err := a.hubRoots(true)
	if err != nil {
		return nil
	}
	v, err := domain.Verify(string(doc), roots, time.Now())
	if err != nil {
		return nil
	}
	return &hubIndex{v: v, doc: string(doc), dir: dir, warn: a.stderr}
}

func hubStatus(ctx context.Context, a *app, args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	dir, err := hubDir(a.env)
	if err != nil {
		return err
	}
	local, err := loadHubLocal(dir)
	if err != nil {
		return err
	}
	x := a.hubCached(dir, local)
	switch seen, ok := local.Indexes[local.Current]; {
	case !ok:
		_, err = fmt.Fprintln(a.stdout, "this machine: no index yet (pclaw hub update)")
	case x == nil:
		_, err = fmt.Fprintf(a.stdout, "this machine: index version %d no longer verifies; it may have expired (pclaw hub update)\n", seen.Version)
	default:
		_, err = fmt.Fprintf(a.stdout, "this machine: index version %d, expires %s\n", seen.Version, seen.ExpiresAt)
	}
	if err != nil {
		return err
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	c := hubClient(s)
	st, err := c.GetHubState(ctx, &pantherclawv1.GetHubStateRequest{})
	if err != nil {
		return hubStatusError(err)
	}
	if st.GetPresent() {
		_, err = fmt.Fprintf(a.stdout, "this org: index version %d\n", st.GetIndexVersion())
	} else {
		_, err = fmt.Fprintln(a.stdout, "this org: nothing installed yet")
	}
	if err != nil {
		return err
	}
	installed, err := hubInstalled(ctx, c)
	if err != nil {
		return err
	}
	for _, in := range installed {
		if _, err := fmt.Fprintf(a.stdout, "%s@%s\t%s\t%s\n", in.GetName(), in.GetVersion(), in.GetResultKind(), in.GetResultRef()); err != nil {
			return err
		}
	}
	if x == nil {
		return nil
	}
	return a.printHubUpdates(x, installed)
}

// hubLoopback reports whether host is this machine.
func hubLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

func hubStatusError(err error) error {
	if connect.CodeOf(err) == connect.CodeNotFound {
		return errors.New("hub: this server has no Hub API; upgrade it")
	}
	return err
}
