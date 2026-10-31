// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bufio"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/gateway/sdk"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
	scdomain "github.com/katocxl/pantherclaw/internal/supplychain/domain"
)

// `pclaw mcp inspect` (G0 M24 D214, F871, HR-584) looks at a stdio MCP server
// before anyone connects it. It runs the server's image on this machine, in
// the sandbox with no credential, no workspace and no route out, lists what
// the server offers, records where it asked to go, and runs the supply-chain
// checks. The only thing that reaches a PantherClaw server is the operator's
// note, with --submit. Everything the server says is UNTRUSTED: nothing here
// acts on it, and only names, addresses and PantherClaw's own notes are
// printed, escaped (HR-583). No known flags is all a result can say (HR-582).

// Bounds on what an inspected server can make this process hold.
const (
	inspectDefaultTimeout = 2 * time.Minute
	maxInspectLine        = 4 << 20
	maxInspectOutput      = 64 << 20
	maxInspectItems       = 1000
	maxInspectPages       = 32
	maxInspectDescription = 64 << 10
	maxInspectNote        = 8 << 10
	maxNoteAttempts       = 16
)

// inspectLimits says what an inspection here cannot know, printed with every
// result.
const inspectLimits = "Not checked here: whether a reviewed package names these tools, changes since an approval, " +
	"and shadowing of tools your org approved. The gateway's inventory checks those. " +
	"Connections past the proxy were dropped by the network and are not listed. " +
	"\"No known flags\" is all this says about a server."

func init() {
	commands["mcp inspect"] = command{
		usage: "mcp inspect [--edge-image REF] [--timeout D] [--format text|json] [--submit ITEM_ID] IMAGE@sha256:… [-- ARGS...]",
		run:   mcpInspect,
	}
}

type inspectFlags struct {
	image, edgeImage, format, submit string
	timeout                          time.Duration
	args                             []string
}

func parseInspect(a *app, args []string) (inspectFlags, error) {
	f := inspectFlags{}
	fs := flag.NewFlagSet("mcp inspect", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	edge, _ := a.env("PANTHERCLAW_SANDBOX_EDGE_IMAGE")
	fs.StringVar(&f.edgeImage, "edge-image", edge, "the edge image id or digest (task sandbox:images; PANTHERCLAW_SANDBOX_EDGE_IMAGE)")
	fs.DurationVar(&f.timeout, "timeout", inspectDefaultTimeout, "how long the inspection may take")
	fs.StringVar(&f.format, "format", "text", "text or json")
	fs.StringVar(&f.submit, "submit", "", "add the result as an operator-reported note on this inventory item (needs a login)")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	rest := fs.Args()
	if len(rest) == 0 || f.edgeImage == "" || f.timeout <= 0 || (f.format != "text" && f.format != "json") {
		return f, errUsage
	}
	f.image, rest = rest[0], rest[1:]
	if len(rest) > 0 {
		// Anything after the image goes to the inspected server, so a flag
		// meant for pclaw must not end up there unnoticed.
		if rest[0] != "--" {
			return f, errUsage
		}
		f.args = rest[1:]
	}
	return f, nil
}

// inspector runs a server and talks to it.
type inspector func(ctx context.Context, f inspectFlags, talk func(context.Context, io.Writer, io.Reader) error) (sandbox.Inspection, error)

func mcpInspect(ctx context.Context, a *app, args []string) error {
	f, err := parseInspect(a, args)
	if err != nil {
		return err
	}
	// A server is only ever an image pinned by digest, on the local engine: a
	// URL, a tag or an npx line names something else on the next run.
	for _, ref := range []string{f.image, f.edgeImage} {
		if _, err := docker.ImageDigest(ref); err != nil {
			return err
		}
	}
	return inspectServer(ctx, a, f, runInspection)
}

// runInspection is the sandbox on this machine's Docker engine. No login is
// read for it: the session, the only thing here that could name a credential,
// belongs to --submit, after the server is gone.
func runInspection(ctx context.Context, f inspectFlags, talk func(context.Context, io.Writer, io.Reader) error) (sandbox.Inspection, error) {
	dc := docker.New(docker.CLI{})
	engine, err := dc.Engine(ctx)
	if err != nil {
		return sandbox.Inspection{}, err
	}
	dir, err := os.MkdirTemp("", "pclaw-inspect-")
	if err != nil {
		return sandbox.Inspection{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	return sandbox.Inspect(ctx, dc, engine, sandbox.InspectOptions{
		Session: ids.NewV7().String(), EdgeImage: f.edgeImage, Image: f.image, Args: f.args, Dir: dir,
	}, talk)
}

func inspectServer(ctx context.Context, a *app, f inspectFlags, run inspector) error {
	var c clients
	if f.submit != "" {
		var err error // a missing login shows before the server runs
		if c, err = a.clients(); err != nil {
			return err
		}
	}
	tctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	var l mcpListing
	seen, err := run(tctx, f, l.talk)
	if err != nil {
		return err
	}
	r := newInspectReport(f.image, l, seen)
	if err := r.print(a.stdout, f.format); err != nil {
		return err
	}
	if f.submit == "" {
		return nil
	}
	if _, err := c.connections.AddInventoryNote(ctx, &pb.AddInventoryNoteRequest{Id: f.submit, Note: r.note()}); err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.stderr, "The note is on the inventory item as your report. It changes nothing about the item or its review.")
	return err
}

// mcpListing is what a server listed.
type mcpListing struct {
	tools, resources, templates []jsontext.Value
	// incomplete names the lists that could not be read to their end.
	incomplete []string
}

// talk speaks MCP's stdio transport: initialize, then the three lists. A list
// the server does not offer is empty; one that fails leaves the rest usable,
// and says so.
func (l *mcpListing) talk(ctx context.Context, in io.Writer, out io.Reader) error {
	if c, ok := out.(io.Closer); ok {
		defer context.AfterFunc(ctx, func() { _ = c.Close() })()
	}
	s := &mcpStdio{w: in, r: bufio.NewReaderSize(io.LimitReader(out, maxInspectOutput), maxInspectLine)}
	if _, err := s.call("initialize", map[string]any{
		"protocolVersion": legacyVersion, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "pclaw-mcp-inspect", "version": "1"},
	}); err != nil {
		return fmt.Errorf("the server did not initialize: %w", err)
	}
	if err := s.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		return fmt.Errorf("the server stopped reading: %w", err)
	}
	for _, list := range []struct {
		method, key string
		into        *[]jsontext.Value
	}{
		{"tools/list", "tools", &l.tools},
		{"resources/list", "resources", &l.resources},
		{"resources/templates/list", "resourceTemplates", &l.templates},
	} {
		err := s.list(list.method, list.key, list.into)
		failed, answered := errors.AsType[*inspectRefusal](err)
		switch {
		case err == nil, answered && failed.Code == methodNotFound:
		case answered:
			l.incomplete = append(l.incomplete, list.method)
		case list.method == "tools/list" && len(l.tools) == 0:
			return fmt.Errorf("the server did not list its tools: %w", err)
		default:
			l.incomplete = append(l.incomplete, list.method)
			return nil // the server's output ended; what it listed stands
		}
	}
	return nil
}

// methodNotFound is JSON-RPC's code for a method a peer does not have.
const methodNotFound = -32601

// inspectRefusal is a JSON-RPC error from the server. Its text is the server's and
// is never shown.
type inspectRefusal struct {
	Code int `json:"code"`
}

func (e *inspectRefusal) Error() string {
	return "the server answered with error " + strconv.Itoa(e.Code)
}

// mcpStdio is one newline-delimited JSON-RPC conversation.
type mcpStdio struct {
	w    io.Writer
	r    *bufio.Reader
	next int
}

func (s *mcpStdio) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.w.Write(append(b, '\n'))
	return err
}

// call sends a request and reads to its answer. A server's own requests get
// method-not-found: the inspector samples nothing, elicits nothing and holds
// no roots. Lines that are not JSON-RPC are skipped.
func (s *mcpStdio) call(method string, params any) (jsontext.Value, error) {
	s.next++
	want := strconv.Itoa(s.next)
	if err := s.send(map[string]any{"jsonrpc": "2.0", "id": s.next, "method": method, "params": params}); err != nil {
		return nil, err
	}
	for {
		line, err := s.r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, errors.New("the server wrote a line over 4 MiB")
		}
		if err != nil && len(line) == 0 {
			return nil, err
		}
		var m struct {
			ID     jsontext.Value  `json:"id"`
			Method jsontext.Value  `json:"method"`
			Result jsontext.Value  `json:"result"`
			Error  *inspectRefusal `json:"error"`
		}
		if json.Unmarshal(line, &m) != nil {
			if err != nil {
				return nil, err
			}
			continue
		}
		switch {
		case len(m.Method) != 0 && len(m.ID) != 0:
			if err := s.send(map[string]any{
				"jsonrpc": "2.0", "id": m.ID, "error": map[string]any{"code": methodNotFound, "message": "method not found"},
			}); err != nil {
				return nil, err
			}
		case string(m.ID) != want:
		case m.Error != nil:
			return nil, m.Error
		default:
			return m.Result.Clone(), nil
		}
	}
}

// list reads a list through its cursors, up to the bounds. Going over a bound
// is an incomplete list, not an error to stop for.
func (s *mcpStdio) list(method, key string, into *[]jsontext.Value) error {
	cursor := ""
	for range maxInspectPages {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		res, err := s.call(method, params)
		if err != nil {
			return err
		}
		var page map[string]jsontext.Value
		if err := json.Unmarshal(res, &page); err != nil {
			return &inspectRefusal{}
		}
		var items []jsontext.Value
		if v, ok := page[key]; ok {
			if err := json.Unmarshal(v, &items); err != nil {
				return &inspectRefusal{}
			}
		}
		if len(*into)+len(items) > maxInspectItems {
			*into = append(*into, items[:maxInspectItems-len(*into)]...)
			return &inspectRefusal{}
		}
		*into = append(*into, items...)
		cursor = ""
		if v, ok := page["nextCursor"]; ok {
			_ = json.Unmarshal(v, &cursor)
		}
		if cursor == "" {
			return nil
		}
	}
	return &inspectRefusal{}
}

// inspectReport is the result. Every string that came from the server is
// escaped, and descriptions are not in it.
type inspectReport struct {
	Image     string         `json:"image"`
	Tools     []inspectEntry `json:"tools"`
	Resources []inspectEntry `json:"resources"`
	Templates []inspectEntry `json:"resource_templates"`
	Attempts  []string       `json:"egress_attempts"`
	Summary   string         `json:"summary"`
	NotRead   []string       `json:"lists_not_read_to_the_end"`
	Limits    string         `json:"limits"`
	result    scdomain.Result
}

// inspectEntry is one listed thing.
type inspectEntry struct {
	Name    string        `json:"name"`
	Digest  string        `json:"digest,omitzero"`
	Summary string        `json:"summary"`
	Flags   []inspectFlag `json:"flags"`
}

// inspectFlag is one check's finding. Its spans are offsets into the listed
// text, which is not repeated here.
type inspectFlag struct {
	Kind     string          `json:"kind"`
	Severity string          `json:"severity"`
	Note     string          `json:"note"`
	Spans    []scdomain.Span `json:"spans,omitzero"`
}

func newInspectReport(image string, l mcpListing, seen sandbox.Inspection) inspectReport {
	r := inspectReport{
		Image: escapeControls(image), Tools: []inspectEntry{}, Resources: []inspectEntry{}, Templates: []inspectEntry{},
		Attempts: []string{}, NotRead: []string{}, Limits: inspectLimits,
	}
	// Here nothing says what a server's tools ought to be: provenance needs a
	// connection's pinned package, so it is left out, not guessed.
	known := scdomain.Known{BuiltIns: sdk.BuiltInNames(), Provenance: true}
	check := func(t scdomain.Tool) inspectEntry {
		res := scdomain.Check(t, known)
		r.result.Flags = append(r.result.Flags, res.Flags...)
		r.result.Partial = r.result.Partial || res.Partial
		e := inspectEntry{Name: escapeControls(t.Name), Digest: t.Digest, Summary: scdomain.Summary(res), Flags: []inspectFlag{}}
		for _, f := range res.Flags {
			e.Flags = append(e.Flags, inspectFlag{Kind: string(f.Kind), Severity: string(f.Severity), Note: escapeControls(f.Note), Spans: f.Spans})
		}
		return e
	}
	for _, raw := range l.tools {
		if t, ok := listedTool(raw); ok {
			r.Tools = append(r.Tools, check(t))
		} else {
			r.result.Partial = true
		}
	}
	for _, raw := range l.resources {
		r.Resources = append(r.Resources, check(listedResource(raw, "uri")))
	}
	for _, raw := range l.templates {
		r.Templates = append(r.Templates, check(listedResource(raw, "uriTemplate")))
	}
	for _, a := range seen.Attempts {
		if a.Kind == sandbox.RouteDirectAPI {
			r.Attempts = append(r.Attempts, escapeControls(a.Locator))
		}
	}
	for _, m := range l.incomplete {
		r.NotRead = append(r.NotRead, m)
		r.result.Partial = true
	}
	r.Summary = scdomain.Summary(r.result)
	return r
}

// listedTool reads a tool as the gateway does: its digest over the whole
// listing, its schema by itself.
func listedTool(raw jsontext.Value) (scdomain.Tool, bool) {
	var n struct {
		Name        string         `json:"name"`
		Description jsontext.Value `json:"description"`
		InputSchema jsontext.Value `json:"inputSchema"`
	}
	digest, err := upstream.ToolDigest(raw)
	if err != nil || json.Unmarshal(raw, &n) != nil || n.Name == "" {
		return scdomain.Tool{}, false
	}
	t := scdomain.Tool{Name: n.Name, IsTool: true, Digest: digest}
	t.Description, t.DescriptionCut = listedText(n.Description)
	switch {
	case len(n.InputSchema) == 0:
	case len(n.InputSchema) > scdomain.MaxInputSchema:
		t.InputSchemaCut = true
	default:
		t.InputSchema = n.InputSchema
		if d, err := upstream.SchemaDigest(n.InputSchema); err == nil {
			t.InputSchemaDigest = d
		}
	}
	return t, true
}

// listedResource reads a resource or a template. Its name is its address.
func listedResource(raw jsontext.Value, field string) scdomain.Tool {
	var m map[string]jsontext.Value
	if json.Unmarshal(raw, &m) != nil {
		return scdomain.Tool{DescriptionCut: true}
	}
	var name string
	_ = json.Unmarshal(m[field], &name)
	t := scdomain.Tool{Name: name}
	t.Description, t.DescriptionCut = listedText(m["description"])
	return t
}

// listedText is a listed description, cut to the bound on a rune boundary. A
// description that is not a string counts as cut: it was not checked.
func listedText(v jsontext.Value) (string, bool) {
	if len(v) == 0 {
		return "", false
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return "", true
	}
	if len(s) <= maxInspectDescription {
		return s, false
	}
	return cutUTF8(s, maxInspectDescription), true
}

func cutUTF8(s string, n int) string {
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func (r inspectReport) print(w io.Writer, format string) error {
	if format == "json" {
		if err := json.MarshalWrite(w, r, json.Deterministic(true)); err != nil {
			return err
		}
		_, err := fmt.Fprintln(w)
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Inspected %s with no credentials and no route out.\n", r.Image)
	section := func(title string, entries []inspectEntry) {
		fmt.Fprintf(&b, "%s: %d\n", title, len(entries))
		for _, e := range entries {
			fmt.Fprintf(&b, "  %s: %s\n", e.Name, e.Summary)
			for _, f := range e.Flags {
				fmt.Fprintf(&b, "    %s %s: %s\n", f.Severity, f.Kind, f.Note)
			}
		}
	}
	section("Tools", r.Tools)
	section("Resources", r.Resources)
	section("Resource templates", r.Templates)
	fmt.Fprintf(&b, "Egress attempts the proxy refused: %d\n", len(r.Attempts))
	for _, a := range r.Attempts {
		fmt.Fprintf(&b, "  %s\n", a)
	}
	for _, m := range r.NotRead {
		fmt.Fprintf(&b, "Not read to the end: %s\n", m)
	}
	fmt.Fprintf(&b, "Result: %s\n%s\n", r.Summary, r.Limits)
	_, err := io.WriteString(w, b.String())
	return err
}

// note is the report for an inventory item, within its 8 KiB. It stays the
// operator's word: the server stores it as UNTRUSTED text.
func (r inspectReport) note() string {
	attempts := r.Attempts
	more := ""
	if len(attempts) > maxNoteAttempts {
		more = fmt.Sprintf(" and %d more", len(attempts)-maxNoteAttempts)
		attempts = attempts[:maxNoteAttempts]
	}
	refused := "none"
	if len(attempts) > 0 {
		refused = strings.Join(attempts, ", ") + more
	}
	s := fmt.Sprintf("pclaw mcp inspect of %s: %d tools, %d resources, %d resource templates. Result: %s. Egress attempts refused: %s.",
		r.Image, len(r.Tools), len(r.Resources), len(r.Templates), r.Summary, refused)
	if len(s) > maxInspectNote {
		s = cutUTF8(s, maxInspectNote)
	}
	return s
}
