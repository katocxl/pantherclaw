// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// jsonNode is a JSON value that keeps its object members in order, so that
// a configuration file `pclaw init` changes keeps everything it does not
// change, and its diff shows only what changed (HR-208).
type jsonNode struct {
	// kind is '{' or '[', or 0 for a scalar in raw.
	kind  byte
	keys  []string
	vals  []*jsonNode
	items []*jsonNode
	raw   jsontext.Value
}

// parseJSONDoc parses a configuration file strictly: one JSON object, no
// duplicate member names, valid UTF-8.
func parseJSONDoc(b []byte) (*jsonNode, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return &jsonNode{kind: '{'}, nil
	}
	d := jsontext.NewDecoder(bytes.NewReader(b))
	n, err := readNode(d)
	if err != nil {
		return nil, err
	}
	if _, err := d.ReadToken(); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one JSON value")
	}
	if n.kind != '{' {
		return nil, errors.New("not a JSON object")
	}
	return n, nil
}

func readNode(d *jsontext.Decoder) (*jsonNode, error) {
	kind := d.PeekKind()
	if kind == jsontext.KindBeginObject {
		if _, err := d.ReadToken(); err != nil {
			return nil, err
		}
		n := &jsonNode{kind: '{'}
		for d.PeekKind() != '}' {
			t, err := d.ReadToken()
			if err != nil {
				return nil, err
			}
			k := t.String() // a token is valid only until the next read
			v, err := readNode(d)
			if err != nil {
				return nil, err
			}
			n.keys, n.vals = append(n.keys, k), append(n.vals, v)
		}
		_, err := d.ReadToken()
		return n, err
	}
	if kind == jsontext.KindBeginArray {
		if _, err := d.ReadToken(); err != nil {
			return nil, err
		}
		n := &jsonNode{kind: '['}
		for d.PeekKind() != ']' {
			v, err := readNode(d)
			if err != nil {
				return nil, err
			}
			n.items = append(n.items, v)
		}
		_, err := d.ReadToken()
		return n, err
	}
	v, err := d.ReadValue()
	if err != nil {
		return nil, err
	}
	return &jsonNode{raw: v.Clone()}, nil
}

// jsonFields is an object with these members, in this order: name, value,
// name, value… Values are nodes or anything jsonOf takes.
func jsonFields(kv ...any) *jsonNode {
	n := &jsonNode{kind: '{'}
	for i := 0; i+1 < len(kv); i += 2 {
		name, _ := kv[i].(string)
		n.set(name, jsonOf(kv[i+1]))
	}
	return n
}

// jsonOf is v as a node; a node is itself.
func jsonOf(v any) *jsonNode {
	if n, ok := v.(*jsonNode); ok {
		return n
	}
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		panic(err) // only values this package builds
	}
	n, err := readNode(jsontext.NewDecoder(bytes.NewReader(b)))
	if err != nil {
		panic(err)
	}
	return n
}

// get returns an object member, or nil.
func (n *jsonNode) get(key string) *jsonNode {
	if n == nil || n.kind != '{' {
		return nil
	}
	for i, k := range n.keys {
		if k == key {
			return n.vals[i]
		}
	}
	return nil
}

// set replaces an object member, or appends it.
func (n *jsonNode) set(key string, v *jsonNode) {
	for i, k := range n.keys {
		if k == key {
			n.vals[i] = v
			return
		}
	}
	n.keys, n.vals = append(n.keys, key), append(n.vals, v)
}

// object returns the member key, adding an empty object when it is
// missing; ok is false when it exists and is not an object.
func (n *jsonNode) object(key string) (*jsonNode, bool) {
	v := n.get(key)
	if v == nil {
		v = &jsonNode{kind: '{'}
		n.set(key, v)
	}
	return v, v.kind == '{'
}

// array is object for an array member.
func (n *jsonNode) array(key string) (*jsonNode, bool) {
	v := n.get(key)
	if v == nil {
		v = &jsonNode{kind: '['}
		n.set(key, v)
	}
	return v, v.kind == '['
}

// str is a string scalar's value, or "".
func (n *jsonNode) str() string {
	if n == nil || n.kind != 0 || n.raw.Kind() != '"' {
		return ""
	}
	var s string
	_ = json.Unmarshal(n.raw, &s)
	return s
}

// bool is whether n is the literal true.
func (n *jsonNode) bool() bool { return n != nil && n.kind == 0 && n.raw.Kind() == 't' }

// encode writes the document with two-space indentation and a final
// newline.
func (n *jsonNode) encode() ([]byte, error) {
	var buf bytes.Buffer
	e := jsontext.NewEncoder(&buf, jsontext.Multiline(true), jsontext.WithIndent("  "))
	if err := writeNode(e, n); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeNode(e *jsontext.Encoder, n *jsonNode) error {
	switch n.kind {
	case '{':
		if err := e.WriteToken(jsontext.BeginObject); err != nil {
			return err
		}
		for i, k := range n.keys {
			if err := e.WriteToken(jsontext.String(k)); err != nil {
				return err
			}
			if err := writeNode(e, n.vals[i]); err != nil {
				return err
			}
		}
		return e.WriteToken(jsontext.EndObject)
	case '[':
		if err := e.WriteToken(jsontext.BeginArray); err != nil {
			return err
		}
		for _, v := range n.items {
			if err := writeNode(e, v); err != nil {
				return err
			}
		}
		return e.WriteToken(jsontext.EndArray)
	}
	return e.WriteValue(n.raw)
}

// likeOriginal gives an encoded document the original file's line endings
// and final newline, so a file Claude Code wrote (two-space indentation)
// changes only where pclaw changed it.
func likeOriginal(original, encoded []byte) []byte {
	if original == nil {
		return encoded
	}
	if !bytes.HasSuffix(original, []byte("\n")) {
		encoded = bytes.TrimSuffix(encoded, []byte("\n"))
	}
	if bytes.Contains(original, []byte("\r\n")) {
		encoded = bytes.ReplaceAll(encoded, []byte("\n"), []byte("\r\n"))
	}
	return encoded
}

// lineDiff shows what changed between two texts as one hunk: the lines
// they share at the start and end are left out. pclaw init only adds, so
// one hunk is what a person needs to review. The diff goes to a terminal,
// a dry run's output or a CI log, so in JSON texts the values under env
// and headers (where tokens live) are shown as "<redacted>"; the file
// itself keeps them.
func lineDiff(name string, before, after []byte) string {
	a, b := strings.Split(string(redactSecrets(before)), "\n"), strings.Split(string(redactSecrets(after)), "\n")
	if len(before) == 0 {
		a = nil
	}
	p := 0
	for p < len(a) && p < len(b) && a[p] == b[p] {
		p++
	}
	s := 0
	for s < len(a)-p && s < len(b)-p && a[len(a)-1-s] == b[len(b)-1-s] {
		s++
	}
	if p == len(a) && p == len(b) {
		return ""
	}
	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s\n@@ line %d @@\n", name, name, p+1)
	for _, l := range a[p : len(a)-s] {
		fmt.Fprintf(&out, "-%s\n", l)
	}
	for _, l := range b[p : len(b)-s] {
		fmt.Fprintf(&out, "+%s\n", l)
	}
	return out.String()
}

// secretMembers are the members whose values hold credentials in Claude
// Code's configuration: environment variables (settings and MCP servers)
// and HTTP headers (MCP servers).
var secretMembers = []string{"env", "headers"}

// redactSecrets is a JSON text with every string inside an env or headers
// member replaced by "<redacted>", and everything else byte for byte, so a
// diff of two redacted texts lines up as the diff of the texts does. Text
// that is not JSON is returned as it is.
func redactSecrets(b []byte) []byte {
	var spans [][2]int64
	d := jsontext.NewDecoder(bytes.NewReader(b))
	if err := findSecrets(d, b, false, &spans); err != nil || len(spans) == 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	at := int64(0)
	for _, s := range spans {
		out = append(append(out, b[at:s[0]]...), `"<redacted>"`...)
		at = s[1]
	}
	return append(out, b[at:]...)
}

// findSecrets reads one value and adds the byte span of each string in it
// that is inside an env or headers member (secret).
func findSecrets(d *jsontext.Decoder, b []byte, secret bool, spans *[][2]int64) error {
	kind := d.PeekKind()
	if kind == jsontext.KindBeginObject {
		if _, err := d.ReadToken(); err != nil {
			return err
		}
		for d.PeekKind() != jsontext.KindEndObject {
			t, err := d.ReadToken()
			if err != nil {
				return err
			}
			if err := findSecrets(d, b, secret || slices.Contains(secretMembers, t.String()), spans); err != nil {
				return err
			}
		}
		_, err := d.ReadToken()
		return err
	}
	if kind == jsontext.KindBeginArray {
		if _, err := d.ReadToken(); err != nil {
			return err
		}
		for d.PeekKind() != jsontext.KindEndArray {
			if err := findSecrets(d, b, secret, spans); err != nil {
				return err
			}
		}
		_, err := d.ReadToken()
		return err
	}
	if !secret || kind != jsontext.KindString {
		return d.SkipValue()
	}
	// The offset is just after the last token; the string starts after the
	// white space and the separator that follow it.
	start := d.InputOffset()
	for start < int64(len(b)) && b[start] != '"' {
		start++
	}
	if err := d.SkipValue(); err != nil {
		return err
	}
	*spans = append(*spans, [2]int64{start, d.InputOffset()})
	return nil
}

// linkTarget is the file a path names: for a link (a settings file kept
// with the person's dotfiles, say), the file it points to, so that the
// file is backed up and replaced where it is and the link stays a link.
// Any other path is itself. A link to nothing is an error: pclaw does not
// guess where its file should be.
func linkTarget(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return path, nil
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("%s is a link pclaw cannot follow (%w); it is left as it is", path, err)
	}
	return target, nil
}

// backupFile copies path, when it exists, to a new file beside it named
// with the time, and returns that name ("" for a file that does not exist
// yet). A link is backed up beside the file it points to. An existing
// backup is never overwritten: a second one in the same second gets a
// counter.
func backupFile(path string, now time.Time) (string, error) {
	path, err := linkTarget(path)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: the user's own configuration
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	base := path + ".pclaw-backup-" + now.UTC().Format("20060102T150405Z")
	name := base
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: beside the user's file
	for i := 2; errors.Is(err, os.ErrExist) && i <= 100; i++ {
		// Another backup in the same second: never overwrite it.
		name = fmt.Sprintf("%s-%d", base, i)
		f, err = os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: beside the user's file
	}
	if err != nil {
		return "", fmt.Errorf("backup of %s: %w", path, err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return "", err
	}
	return name, f.Close()
}

// writeAtomically replaces path with b through a temporary file in the same
// directory, keeping the file's mode (0600 for a new file). A link is
// followed: the file it points to is replaced in its own directory, and
// the link stays.
func writeAtomically(path string, b []byte) error {
	path, err := linkTarget(path)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".pclaw-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(mode); err != nil && !isWindows() {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// itemsOf is an array's items, or none.
func (n *jsonNode) itemsOf() []*jsonNode {
	if n == nil || n.kind != '[' {
		return nil
	}
	return n.items
}
