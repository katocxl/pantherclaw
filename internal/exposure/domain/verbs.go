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
	//exhaustive:ignore // read and anything unrecognized cost least
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
	transferWords = []string{"transfer", "send", "pay", "payout", "refund"}
	exportWords   = []string{"export", "upload", "share", "publish"}
)

// Bases say why an operation got a verb (D45, F257).
const (
	BasisAccess        = "ACCESS"         // the definition's access class
	BasisEffectKind    = "EFFECT_KIND"    // an effect kind's last segment; Classified.Kind names it
	BasisDefaultUpdate = "DEFAULT_UPDATE" // a write nothing else classifies
	BasisDelegation    = "DELEGATION"     // the grant's delegation depth
	BasisScope         = "SCOPE_LEVEL"    // a credential scope's level
)

// Classified is one verb an operation gets, and why.
type Classified struct {
	Verb  Verb
	Basis string
	// Kind is the matched effect kind (EFFECT_KIND only).
	Kind string
}

// Explain renders the basis as stored: "EFFECT_KIND:<kind>" or the basis.
func (c Classified) Explain() string {
	if c.Kind != "" {
		return c.Basis + ":" + c.Kind
	}
	return c.Basis
}

// lastSegment is the last dot-separated segment of an effect kind, lower
// case.
func lastSegment(kind string) string {
	if i := strings.LastIndexByte(kind, '.'); i >= 0 {
		kind = kind[i+1:]
	}
	return strings.ToLower(kind)
}

// Classify maps an operation to matrix verbs from its definition (D28,
// D45), matching each effect kind's last segment case-insensitively:
//   - a read reads; it also exports when the connection's destination
//     class is public;
//   - an effect ending in export, upload, share or publish exports, and
//     counts under its write verb too;
//   - a write effect ending in delete, remove, destroy or purge deletes;
//     in transfer, send, pay, payout or refund transfers; any other write
//     updates, and a write nothing classifies is an update (never
//     dropped).
//
// Each verb appears once, with the first basis that gave it.
func Classify(op Operation, c Connection) []Classified {
	var out []Classified
	add := func(x Classified) {
		if !slices.ContainsFunc(out, func(y Classified) bool { return y.Verb == x.Verb }) {
			out = append(out, x)
		}
	}
	read := op.Access == defs.AccessRead
	if read {
		add(Classified{Verb: VerbRead, Basis: BasisAccess})
		if c.DestinationClass == "public" {
			add(Classified{Verb: VerbExport, Basis: BasisAccess})
		}
	}
	for _, e := range op.Effects {
		s := lastSegment(e)
		switch {
		case slices.Contains(exportWords, s):
			add(Classified{Verb: VerbExport, Basis: BasisEffectKind, Kind: e})
			if !read {
				add(Classified{Verb: VerbUpdate, Basis: BasisEffectKind, Kind: e})
			}
		case read:
		case slices.Contains(deleteWords, s):
			add(Classified{Verb: VerbDelete, Basis: BasisEffectKind, Kind: e})
		case slices.Contains(transferWords, s):
			add(Classified{Verb: VerbTransfer, Basis: BasisEffectKind, Kind: e})
		case s != "none":
			add(Classified{Verb: VerbUpdate, Basis: BasisEffectKind, Kind: e})
		}
	}
	if !read && !slices.ContainsFunc(out, func(x Classified) bool { return x.Verb != VerbExport }) {
		add(Classified{Verb: VerbUpdate, Basis: BasisDefaultUpdate})
	}
	slices.SortFunc(out, func(a, b Classified) int { return slices.Index(AllVerbs, a.Verb) - slices.Index(AllVerbs, b.Verb) })
	return out
}

// Verbs lists Classify's verbs.
func Verbs(op Operation, c Connection) []Verb {
	cs := Classify(op, c)
	out := make([]Verb, len(cs))
	for i, x := range cs {
		out[i] = x.Verb
	}
	return out
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
