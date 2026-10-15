// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"strings"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// Verb is a matrix column (F256).
type Verb string

// Verbs, by consequence: a transfer or a delete costs most.
const (
	VerbRead     Verb = "read"
	VerbExport   Verb = "export"
	VerbUpdate   Verb = "update"
	VerbDelete   Verb = "delete"
	VerbTransfer Verb = "transfer"
	VerbDelegate Verb = "delegate"
)

// AllVerbs lists the matrix columns in display order.
var AllVerbs = []Verb{VerbRead, VerbExport, VerbUpdate, VerbDelete, VerbTransfer, VerbDelegate}

// Consequence ranks a verb: higher costs more.
func (v Verb) Consequence() int {
	switch v {
	case VerbTransfer:
		return 5
	case VerbDelete:
		return 4
	case VerbExport:
		return 3
	case VerbUpdate:
		return 2
	case VerbDelegate:
		return 1
	default:
		return 0
	}
}

var (
	deleteWords   = []string{"delete", "remove", "destroy", "purge"}
	transferWords = []string{"transfer", "send", "pay", "payout"}
)

// lastSegment is the last dot-separated segment of an effect kind.
func lastSegment(kind string) string {
	if i := strings.LastIndexByte(kind, '.'); i >= 0 {
		return kind[i+1:]
	}
	return kind
}

// Verbs maps an operation to matrix verbs from its definition (D28): a read
// reads, and exports when the connection's destination class is public; a
// write deletes or transfers when an effect kind ends in such a word, and
// otherwise (or as well) updates. A write whose effects say nothing is an
// update: a write is never dropped.
func Verbs(op Operation, c Connection) []Verb {
	if op.Access == defs.AccessRead {
		if c.DestinationClass == "public" {
			return []Verb{VerbRead, VerbExport}
		}
		return []Verb{VerbRead}
	}
	var out []Verb
	for _, e := range op.Effects {
		switch s := lastSegment(e); {
		case slices.Contains(deleteWords, s):
			out = append(out, VerbDelete)
		case slices.Contains(transferWords, s):
			out = append(out, VerbTransfer)
		default:
			out = append(out, VerbUpdate)
		}
	}
	if len(out) == 0 {
		out = []Verb{VerbUpdate}
	}
	slices.SortFunc(out, func(a, b Verb) int { return slices.Index(AllVerbs, a) - slices.Index(AllVerbs, b) })
	return slices.Compact(out)
}

// Group is an operation's resource group: its target type, qualified by
// the connection (two connections' "repository" are different resources).
func Group(op Operation, c Connection) string {
	t := op.TargetType
	if t == "" {
		t = "untyped"
	}
	if c.Name == "" {
		return t
	}
	return c.Name + "/" + t
}
