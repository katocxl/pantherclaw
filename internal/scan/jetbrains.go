// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scan

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// JetBrains AI Assistant (the AI Assistant plugin, com.intellij.ml.llm, MCP
// client since 2025.1; Junie is a separate client) keeps its MCP servers in
// the places below. The formats are taken from the plugin's persisted-state
// classes, package com.intellij.ml.llm.mcp.client.settings, in builds
// 252.23892.530 (IDE 2025.2.0), 252.28539.116 (the last 2025.2 build) and
// 262.10968.223 (2026.2), from plugins.jetbrains.com:
//
//   - IDE level: options/llm.mcpServers.xml in each IDE's configuration
//     directory, <config>/JetBrains/<Product><Version>, where <config> is
//     %APPDATA% on Windows, ~/Library/Application Support on macOS and
//     $XDG_CONFIG_HOME or ~/.config on Linux, as os.UserConfigDir returns
//     ("Directories used by the IDE",
//     https://www.jetbrains.com/help/idea/directories-used-by-the-ide-to-store-settings-caches-plugins-and-logs.html#config-directory).
//     Every installed IDE and version has its own. The component is
//     McpApplicationServerCommands (@State of McpApplicationServerCommandService
//     in 2025.2, McpApplicationServerConfigurationService in 2026.2).
//   - Project level: .idea/workspace.xml ($WORKSPACE_FILE$), component
//     McpProjectServerCommands, or .idea/.idea.<Solution>/.idea/workspace.xml
//     for Rider, as committed Rider projects show.
//   - Since 2025.3 (https://youtrack.jetbrains.com/issue/LLM-22682) the
//     definitions are JSON in ~/.ai/mcp/mcp.json and <project>/.ai/mcp/mcp.json.
//     Gson reads the file as
//     {"mcpServers": {name: {command, args, env, type, url, headers}}} or, when
//     it has no "mcpServers", as that map itself
//     (McpServerConfigurationServiceBase.Companion.parseConfigurations); a
//     server with a command is local, one with only a URL is remote.
//   - Those paths are the registry keys llm.mcp.client.global.mcp.json.path
//     (under the user's home) and llm.mcp.client.project.mcp.json.path (under
//     the project directory), both ".ai/mcp/mcp.json" by default; Java's
//     Path.resolve keeps an absolute value whole. The IntelliJ platform keeps
//     a changed registry value in each IDE's options/ide.general.xml, as
//     <entry key="…" value="…" source="USER" /> in component "Registry"
//     (RegistryManagerImpl's @State, Registry.getState and fromState in
//     github.com/JetBrains/intellij-community). A -D system property in the
//     IDE's .vmoptions sets a key the registry has not stored
//     (RegistryValue.resolveRequiredValue); the scan does not read it.
//     early-access-registry.txt holds only keys read through
//     EarlyAccessRegistryManager, and AI Assistant reads these with
//     Registry.stringValue.
//
// The XML component's entries have had three layouts:
//
//	<component name="McpProjectServerCommands">
//	  <McpServerCommand sourceId="UserConfigurationSource">   2025.1, 2025.2
//	    <option name="name" value="nx-mcp" />
//	    <option name="programPath" value="npx.cmd" />
//	    <option name="arguments" value="-y nx-mcp@latest" />
//	    <envs><env name="TOKEN" value="…" /></envs>
//	  </McpServerCommand>
//	  <commands><McpServerCommand>…</McpServerCommand></commands>   later
//	  <urls>
//	    <McpServerURL sourceId="UserConfigurationSource">
//	      <option name="name" value="remote" />
//	      <option name="url" value="https://…" />
//	      <option name="headers"><map><entry key="Authorization" value="…" /></map></option>
//	    </McpServerURL>
//	  </urls>
//	</component>
//
// 2025.2 writes the first layout, as committed 2025.1 files show it too, and
// has no remote servers (McpServerCommandServiceBase.getState;
// McpServerCommandServiceBaseKt serializes each command with XmlSerializer
// and its environment with EnvironmentVariablesData.writeExternal). 2026.2
// moves the second layout to mcp.json once
// (McpServerConfigurationServiceBase.loadOldConfigurations reads each child
// of <commands> as an McpServerCommand and each child of <urls> as an
// McpServerURL, whose headers are a map); no build that writes it was
// examined. From 2025.3, as committed files and 2026.2's getState show,
// <commands> and <urls> hold McpServerConfigurationProperties entries with
// state only ("name", "enabled", "source", "userOverride",
// "allowedToolsNames"); an entry with neither a command nor a URL is
// skipped, since that server is read from mcp.json. options/McpToolsStoreService.xml is not AI Assistant's (no build
// has the class) and caches servers' status and tools, not their
// definitions, so it is not read.

// jetBrainsComponents name the AI Assistant's MCP component in the IDE's
// llm.mcpServers.xml and in a project's workspace.xml.
var jetBrainsComponents = []string{"McpApplicationServerCommands", "McpProjectServerCommands"}

// jetBrainsConfigs lists the AI Assistant files of every IDE and version in
// dir (<config>/JetBrains).
func jetBrainsConfigs(dir string) []string {
	var out []string
	for _, ide := range entries(dir, "") {
		out = append(out, filepath.Join(ide, "options", "llm.mcpServers.xml"))
	}
	return out
}

// The registry keys that move the AI Assistant's mcp.json under the user's
// home directory and under a project's.
const (
	jetBrainsGlobalMCPJSON  = "llm.mcp.client.global.mcp.json.path"
	jetBrainsProjectMCPJSON = "llm.mcp.client.project.mcp.json.path"
)

// jetBrainsMCPJSONPaths returns the mcp.json paths that the registries of
// the IDEs in dir (<config>/JetBrains) set, for the home directory (global)
// and for projects, each once. An empty value, which names the directory
// itself, is left out.
func jetBrainsMCPJSONPaths(dir string, read func(string) []byte) (global, project []string) {
	for _, ide := range entries(dir, "") {
		reg := jetBrainsRegistry(read(filepath.Join(ide, "options", "ide.general.xml")))
		if p := reg[jetBrainsGlobalMCPJSON]; p != "" && !slices.Contains(global, p) {
			global = append(global, p)
		}
		if p := reg[jetBrainsProjectMCPJSON]; p != "" && !slices.Contains(project, p) {
			project = append(project, p)
		}
	}
	return global, project
}

// jetBrainsRegistry reads the registry values an IDE keeps in
// ide.general.xml, the last of each key as Registry.loadState does, or
// returns nil for a file that is not well formed.
func jetBrainsRegistry(b []byte) map[string]string {
	doc := parseXML(b)
	if doc == nil {
		return nil
	}
	reg := map[string]string{}
	for _, top := range doc.kids { // <application>
		for _, c := range top.kids {
			if v, _ := c.attr("name"); c.name != "component" || v != "Registry" {
				continue
			}
			for _, e := range c.kids {
				if k, v, ok := e.pair(); ok && e.name == "entry" {
					reg[k] = v
				}
			}
		}
	}
	return reg
}

// resolvePath resolves p against dir as Java's Path.resolve does: an
// absolute p is kept, and on Windows a p rooted without a drive (\dir) takes
// dir's drive, and one relative to dir's drive (C:dir) is joined to dir. A p
// relative to another drive's working directory gives "".
func resolvePath(dir, p string) string {
	vol := filepath.VolumeName(p)
	switch {
	case filepath.IsAbs(p):
		return filepath.Clean(p)
	case vol != "" && !strings.EqualFold(vol, filepath.VolumeName(dir)):
		return ""
	case vol != "":
		return filepath.Join(dir, p[len(vol):])
	case p != "" && os.IsPathSeparator(p[0]):
		return filepath.Join(filepath.VolumeName(dir), p)
	}
	return filepath.Join(dir, p)
}

// jetBrainsWorkspaces lists a project's workspace.xml files: .idea's, and
// Rider's per solution.
func jetBrainsWorkspaces(project string) []string {
	idea := filepath.Join(project, ".idea")
	out := []string{filepath.Join(idea, "workspace.xml")}
	for _, sln := range entries(idea, ".idea.") {
		out = append(out, filepath.Join(sln, ".idea", "workspace.xml"))
	}
	return out
}

// entries lists the paths in dir whose names start with prefix, sorted. They
// are not checked to be directories, so a symlinked IDE directory is kept;
// reading a file under a non-directory fails later.
func entries(dir, prefix string) []string {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, de := range des {
		if strings.HasPrefix(de.Name(), prefix) {
			out = append(out, filepath.Join(dir, de.Name()))
		}
	}
	return out
}

// fromJetBrainsXML reads the AI Assistant's MCP servers from an XML options
// file into the mcpServers form of the JSON clients, or returns nil for a
// file that is not well formed.
func fromJetBrainsXML(b []byte) map[string]any {
	doc := parseXML(b)
	if doc == nil {
		return nil
	}
	var list []*xmlNode
	for _, top := range doc.kids { // <application> or <project>
		for _, c := range top.kids {
			if v, _ := c.attr("name"); c.name != "component" || !slices.Contains(jetBrainsComponents, v) {
				continue
			}
			for _, e := range c.kids {
				if e.name == "commands" || e.name == "urls" {
					list = append(list, e.kids...)
				} else {
					list = append(list, e)
				}
			}
		}
	}
	servers := map[string]any{}
	for _, e := range list {
		if name, s := jetBrainsServer(e); s != nil {
			servers[name] = s
		}
	}
	return map[string]any{"mcpServers": servers}
}

// jetBrainsServers returns the servers of an AI Assistant configuration: its
// "mcpServers" object or, for an mcp.json without one, the whole object when
// every member is an object (Gson fails the file otherwise).
func jetBrainsServers(doc map[string]any) map[string]any {
	if _, ok := doc["mcpServers"]; ok {
		return member(doc, []string{"mcpServers"})
	}
	for _, v := range doc {
		if _, ok := v.(map[string]any); !ok {
			return nil
		}
	}
	return doc
}

// jetBrainsServer reads one entry into the JSON form: its options (the first
// of each name), the variables of its <envs> list and the entries of its
// headers map. It returns nil for an entry with no name, or with neither a
// command nor a URL. The arguments are not read: tokens are passed there.
func jetBrainsServer(e *xmlNode) (string, map[string]any) {
	opts := map[string]string{}
	env, headers := map[string]any{}, map[string]any{}
	for _, c := range e.kids {
		label, _ := c.attr("name")
		switch {
		case c.name == "envs": // <env name value/>
			c.pairs(env)
		case c.name == "option" && label == "headers": // <map><entry key value/></map>
			c.pairs(headers)
		case c.name == "option":
			if k, v, ok := c.pair(); ok {
				if _, seen := opts[k]; !seen {
					opts[k] = v
				}
			}
		}
	}
	s := map[string]any{}
	if cmd := opts["programPath"]; cmd != "" {
		s["command"] = cmd
	}
	if u := opts["url"]; u != "" {
		s["url"] = u
	}
	if opts["name"] == "" || len(s) == 0 {
		return "", nil
	}
	if len(env) > 0 {
		s["env"] = env
	}
	if len(headers) > 0 {
		s["headers"] = headers
	}
	return opts["name"], s
}

// xmlNode is one element of an XML document.
type xmlNode struct {
	name  string
	attrs []xml.Attr
	kids  []*xmlNode
}

func (n *xmlNode) attr(name string) (string, bool) {
	for _, a := range n.attrs {
		if a.Name.Local == name {
			return a.Value, true
		}
	}
	return "", false
}

// pair reads a name="…" (or key="…") value="…" element.
func (n *xmlNode) pair() (k, v string, ok bool) {
	k, _ = n.attr("name")
	if k == "" {
		k, _ = n.attr("key")
	}
	v, ok = n.attr("value")
	return k, v, ok && k != ""
}

// pairs adds the pairs at any depth under n to list.
func (n *xmlNode) pairs(list map[string]any) {
	for _, kid := range n.kids {
		if k, v, ok := kid.pair(); ok {
			list[k] = v
		}
		kid.pairs(list)
	}
}

// parseXML reads an XML document into a tree under an unnamed root, or
// returns nil for one that is not well formed or is nested deeper than
// MaxNesting (HR-100). encoding/xml reads no DTD and expands only the five
// predefined entities, so a document can neither include a file nor grow by
// entity expansion; any other entity is an error.
func parseXML(b []byte) *xmlNode {
	d := xml.NewDecoder(bytes.NewReader(b))
	stack := []*xmlNode{{}}
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) > MaxNesting {
				return nil
			}
			n := &xmlNode{name: t.Name.Local, attrs: t.Copy().Attr}
			parent := stack[len(stack)-1]
			parent.kids = append(parent.kids, n)
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		}
	}
	if len(stack) != 1 {
		return nil
	}
	return stack[0]
}
