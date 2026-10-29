// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"regexp"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// transcriptName matches a name that would carry an agent's transcript or
// its model reasoning.
var transcriptName = regexp.MustCompile(`(?i)transcript|reasoning|chain_of_thought`)

// TestAPICarriesNoTranscript: PantherClaw records what an agent did, never
// what it said or thought, so no message, field, oneof or enum of the API
// (proto/pantherclaw/v1) is named for a transcript, reasoning or a chain of
// thought (rows26 D23).
// Covers: F236
func TestAPICarriesNoTranscript(t *testing.T) {
	files := 0
	protoregistry.GlobalFiles.RangeFilesByPackage("pantherclaw.v1", func(f protoreflect.FileDescriptor) bool {
		files++
		check := func(kind string, d protoreflect.Descriptor) {
			if transcriptName.MatchString(string(d.Name())) {
				t.Errorf("%s: %s %s is named for a transcript or reasoning", f.Path(), kind, d.FullName())
			}
		}
		var messages func(ms protoreflect.MessageDescriptors)
		enums := func(es protoreflect.EnumDescriptors) {
			for i := range es.Len() {
				e := es.Get(i)
				check("enum", e)
				for j := range e.Values().Len() {
					check("enum value", e.Values().Get(j))
				}
			}
		}
		messages = func(ms protoreflect.MessageDescriptors) {
			for i := range ms.Len() {
				m := ms.Get(i)
				check("message", m)
				for j := range m.Fields().Len() {
					check("field", m.Fields().Get(j))
				}
				for j := range m.Oneofs().Len() {
					check("oneof", m.Oneofs().Get(j))
				}
				enums(m.Enums())
				messages(m.Messages())
			}
		}
		messages(f.Messages())
		enums(f.Enums())
		for i := range f.Services().Len() {
			s := f.Services().Get(i)
			check("service", s)
			for j := range s.Methods().Len() {
				check("method", s.Methods().Get(j))
			}
		}
		return true
	})
	if files < 50 {
		t.Fatalf("only %d files of pantherclaw.v1 are registered", files)
	}
}

// TestTranscriptNameMatches keeps the pattern honest.
// Covers: F236
func TestTranscriptNameMatches(t *testing.T) {
	for _, n := range []string{"transcript", "agent_transcript", "RunTranscript", "Reasoning", "chain_of_thought"} {
		if !transcriptName.MatchString(n) {
			t.Errorf("%q does not match", n)
		}
	}
	for _, n := range []string{"task_ref", "reason", "reason_code", "chain"} {
		if transcriptName.MatchString(n) {
			t.Errorf("%q matches", n)
		}
	}
}
