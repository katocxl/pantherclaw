// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package manifest

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	pcbrowser "github.com/katocxl/pantherclaw/packages/pc-browser"
	pccomputer "github.com/katocxl/pantherclaw/packages/pc-computer"
)

// goldenPackage pins a package's canonical form and every definition
// digest (HR-124).
func goldenPackage(t *testing.T, base string, raw []byte) *domain.Package {
	t.Helper()
	p, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := Canonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, base+".canonical.json", append(canon, '\n'))
	var digests strings.Builder
	for _, d := range p.Definitions {
		fmt.Fprintf(&digests, "%s %s\n", d.Operation, d.Digest)
	}
	golden(t, base+".digests", []byte(digests.String()))
	return p
}

// TestHR124_PcBrowserGolden pins the reviewed meaning of pc.browser (G0 M33
// D974): its canonical form and every definition digest.
func TestHR124_PcBrowserGolden(t *testing.T) {
	p := goldenPackage(t, "pc-browser", pcbrowser.Package)
	if p.Name != pcbrowser.Name || p.Version != pcbrowser.Version {
		t.Fatalf("decoded %s %s", p.Name, p.Version)
	}
}

// TestHR124_PcComputerGolden pins the reviewed meaning of pc.computer (G0
// M33 D984).
func TestHR124_PcComputerGolden(t *testing.T) {
	p := goldenPackage(t, "pc-computer", pccomputer.Package)
	if p.Name != pccomputer.Name || p.Version != pccomputer.Version {
		t.Fatalf("decoded %s %s", p.Name, p.Version)
	}
}

// browserOps is D974: each operation with its access, hook tool, route,
// effect, material params, required params and the param that is the target.
var browserOps = map[string]struct {
	access   domain.Access
	tool     string
	route    string
	effect   string
	material []string
	required []string
}{
	"browser.navigate": {
		domain.AccessRead, "browser_navigate", "browser-navigate", "browser.navigate",
		[]string{"call", "query_bytes", "url"},
		[]string{"call", "url"},
	},
	"browser.form.submit": {
		domain.AccessWrite, "browser_submit", "browser-submit", "browser.submit",
		[]string{"call", "fields", "method", "page_url", "secret_fields", "url"},
		[]string{"call", "secret_fields", "url"},
	},
	"browser.download": {
		domain.AccessWrite, "browser_download", "browser-download", "file.download",
		[]string{"call", "filename", "page_url", "url"},
		[]string{"call", "url"},
	},
	"browser.click": {
		domain.AccessWrite, "browser_click", "browser-click", "browser.click",
		[]string{"call", "label", "page_url", "selector"},
		[]string{"call", "page_url", "selector"},
	},
	"browser.takeover": {
		domain.AccessWrite, "browser_takeover", "browser-takeover", "browser.takeover",
		[]string{"call", "minutes", "page_url"},
		[]string{"call", "minutes", "page_url"},
	},
}

// checkIrreversibleHookOp checks the facts every pc.browser and pc.computer
// operation shares: irreversible, deduped by params.call, not retry safe,
// reconciled when unknown, one hook mapping, no dispatch.
func checkIrreversibleHookOp(t *testing.T, d domain.Definition) {
	t.Helper()
	if d.Reversibility != domain.Irreversible || !slices.Equal(d.Dedupe, []string{"params.call"}) ||
		d.Retry.Safe || d.Retry.OnUnknown != domain.OnUnknownReconcile || d.Dispatch != nil ||
		len(d.Mappings) != 1 || d.Mappings[0].Channel != domain.ChannelHook {
		t.Errorf("%s: reversibility %s dedupe %v retry %+v dispatch %v mappings %+v",
			d.Operation, d.Reversibility, d.Dedupe, d.Retry, d.Dispatch, d.Mappings)
	}
	if c := d.Params["call"]; c.Type != domain.TypeIdentifier || !c.Material || !c.Required || c.Pattern != `^[A-Za-z0-9_-]{1,128}$` {
		t.Errorf("%s: call %+v", d.Operation, c)
	}
}

func sortedMaterial(d domain.Definition) (material, required []string) {
	for name, p := range d.Params {
		if p.Material {
			material = append(material, name)
		}
		if p.Required {
			required = append(required, name)
		}
	}
	slices.Sort(material)
	slices.Sort(required)
	return material, required
}

// TestHR745_PcBrowserIsTheReviewedShape: pc.browser has exactly the five
// D974 operations, each with target browser.site (the URL's host, no
// account), its access, effect, hook tool and route, irreversible and
// deduped by params.call; field values never are a param (only names and
// secret_fields), and user_agent and accept_language are not material.
func TestHR745_PcBrowserIsTheReviewedShape(t *testing.T) {
	p, err := Decode(pcbrowser.Package)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Definitions) != len(browserOps) {
		t.Fatalf("%d definitions, want %d", len(p.Definitions), len(browserOps))
	}
	host := regexp.MustCompile(`^([a-z0-9-]{1,63}\.)*[a-z0-9-]{1,63}$|^\d{1,3}(\.\d{1,3}){3}$|^\[[0-9a-f:.]{2,45}\]$`)
	for _, d := range p.Definitions {
		w, ok := browserOps[d.Operation]
		if !ok {
			t.Errorf("unexpected operation %s", d.Operation)
			continue
		}
		checkIrreversibleHookOp(t, d)
		if d.Target.Type != "browser.site" || d.Target.IDPattern != host.String() || d.Target.Account != domain.PresenceNone {
			t.Errorf("%s: target %+v", d.Operation, d.Target)
		}
		if d.Access != w.access || len(d.Effects) != 1 || d.Effects[0].Kind != w.effect {
			t.Errorf("%s: access %s effects %+v", d.Operation, d.Access, d.Effects)
		}
		if m := d.Mappings[0]; m.Tool != w.tool || m.Route != w.route {
			t.Errorf("%s: mapping %+v", d.Operation, m)
		}
		material, required := sortedMaterial(d)
		if !slices.Equal(material, w.material) || !slices.Equal(required, w.required) {
			t.Errorf("%s: material %v required %v, want %v %v", d.Operation, material, required, w.material, w.required)
		}
		for name, ps := range d.Params {
			if strings.Contains(name, "value") || strings.Contains(name, "password") || strings.Contains(name, "content") {
				t.Errorf("%s: param %s could carry page content (HR-754)", d.Operation, name)
			}
			if (name == "url" || name == "page_url") && ps.Type != domain.TypeURL {
				t.Errorf("%s: %s is %s, not url (HR-748)", d.Operation, name, ps.Type)
			}
		}
	}
	nav := p.Definitions[slices.IndexFunc(p.Definitions, func(d domain.Definition) bool { return d.Operation == "browser.navigate" })]
	if nav.Params["user_agent"].Material || nav.Params["accept_language"].Material {
		t.Error("user_agent and accept_language are not material (D974)")
	}
	sub := p.Definitions[slices.IndexFunc(p.Definitions, func(d domain.Definition) bool { return d.Operation == "browser.form.submit" })]
	if f := sub.Params["fields"]; f.Type != domain.TypeIdentifierList || f.MaxItems != 64 || f.Pattern != `^[A-Za-z0-9_.:\[\]-]{1,64}$` {
		t.Errorf("fields %+v", f)
	}
	if s := sub.Params["secret_fields"]; s.Type != domain.TypeBoolean {
		t.Errorf("secret_fields %+v", s)
	}
	tk := p.Definitions[slices.IndexFunc(p.Definitions, func(d domain.Definition) bool { return d.Operation == "browser.takeover" })]
	if m := tk.Params["minutes"]; m.Type != domain.TypeInteger || m.Min != "1" || m.Max != "10" || m.Unit != "count" {
		t.Errorf("minutes %+v", m)
	}
}

// TestHR758_PcComputerIsTheReviewedShape: pc.computer has one operation,
// computer.input on computer.desktop "local", irreversible and deduped by
// params.call, with its D984 kinds and the coordinates not material.
func TestHR758_PcComputerIsTheReviewedShape(t *testing.T) {
	p, err := Decode(pccomputer.Package)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Definitions) != 1 {
		t.Fatalf("%d definitions", len(p.Definitions))
	}
	d := p.Definitions[0]
	checkIrreversibleHookOp(t, d)
	if d.Operation != "computer.input" || d.Access != domain.AccessWrite || d.Target.Type != "computer.desktop" ||
		d.Target.IDPattern != "^local$" || d.Target.Account != domain.PresenceNone || d.Mappings[0].Tool != "computer" ||
		d.Mappings[0].Route != "computer-input" || len(d.Effects) != 1 || d.Effects[0].Kind != "computer.input" {
		t.Fatalf("decoded %+v", d)
	}
	kinds := []string{"click", "double_click", "triple_click", "drag", "press", "release", "type", "key", "scroll", "move"}
	if k := d.Params["kind"]; !slices.Equal(k.Values, kinds) || !k.Required || !k.Material {
		t.Errorf("kind %+v", k)
	}
	if d.Params["x"].Material || d.Params["y"].Material || d.Params["button"].Required {
		t.Errorf("x %+v y %+v button %+v", d.Params["x"], d.Params["y"], d.Params["button"])
	}
	if d.Params["text"].Type != domain.TypeContent || d.Params["keys"].Type != domain.TypeContent {
		t.Errorf("text and keys are content (D974a): %+v %+v", d.Params["text"], d.Params["keys"])
	}
}

// TestHR745_NoTemplateNamesABrowserOrComputerOperation: no template or
// hub item grants a pc.browser or pc.computer operation by default (D974).
func TestHR745_NoTemplateNamesABrowserOrComputerOperation(t *testing.T) {
	ops := []string{"computer.input"}
	for op := range browserOps {
		ops = append(ops, op)
	}
	seen := 0
	for _, root := range []string{"../../../templates", "../../../hub/items"} {
		err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return err
			}
			if ext := filepath.Ext(path); ext != ".json" && ext != ".yaml" && ext != ".yml" {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			seen++
			for _, op := range ops {
				if strings.Contains(string(b), `"`+op+`"`) || strings.Contains(string(b), " "+op+"\n") ||
					strings.Contains(string(b), "["+op) || strings.Contains(string(b), " "+op+",") || strings.Contains(string(b), " "+op+"]") {
					t.Errorf("%s names %s", path, op)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if seen == 0 {
		t.Fatal("no template read")
	}
}
