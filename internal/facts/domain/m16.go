// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// Classification facts and the built-in signals provider (G0 M16 D80, D82;
// HR-435, HR-441).
//
//   - A declaration's kind is a value (the default) or a classification:
//     the data class of its target, an identifier fact whose value is one
//     of the data classes. The pipeline reads pc.classification about an
//     action's target; it can only raise the class of a read, never lower
//     it, and never allows anything.
//   - A fact carries its provenance, the source and the method that
//     established it; a classification fact is refused without both.
//   - The built-in provider pc.signals is PantherClaw's own: the Shared
//     Signals receiver writes pc.identity.risk about a person through it.
//     It has neither a service account nor a gateway, no RPC can create
//     it, and no other provider may declare pc.identity.risk or take its
//     name.

// Kind is what a declared fact says.
type Kind string

// Kinds. The zero value is KindValue.
const (
	KindValue          Kind = "value"
	KindClassification Kind = "classification"
)

// Of returns the kind, with the zero value as KindValue.
func (k Kind) Of() Kind {
	if k == "" {
		return KindValue
	}
	return k
}

// Reserved names.
const (
	// NameClassification is the classification fact the pipeline reads
	// about an action's target (D80).
	NameClassification = "pc.classification"
	// NameIdentityRisk is the identity-risk fact about user:<id> (D82).
	NameIdentityRisk = "pc.identity.risk"
	// SubjectUser is the subject type of a fact about a person.
	SubjectUser = "user"
	// BuiltinProvider is the name of the built-in provider.
	BuiltinProvider = "pc.signals"
	// MaxSourceLen bounds a fact's source.
	MaxSourceLen = 128
)

// Methods are how a fact may be established.
var Methods = []string{"manual", "rule", "model"}

// reservedFor reports whether a fact name is reserved for the built-in
// provider (compared with dots as underscores, as policies name it).
func reservedFor(name string) bool { return CELName(name) == CELName(NameIdentityRisk) }

// validSources checks the provider's source: exactly one of a service
// account, a gateway and connection, or built in, and the built-in name
// only for the built-in provider.
func (p Provider) validSources() bool {
	n := 0
	for _, set := range []bool{!p.ServiceAccountID.IsZero(), !p.GatewayID.IsZero() && !p.ConnectionID.IsZero(), p.Builtin} {
		if set {
			n++
		}
	}
	if n != 1 || p.GatewayID.IsZero() != p.ConnectionID.IsZero() {
		return false
	}
	return p.Builtin == (p.Name == BuiltinProvider)
}

// validDeclaration checks what M16 adds to a declaration: its kind, and
// that only the built-in provider declares a reserved name.
func (p Provider) validDeclaration(d Declaration) error {
	switch {
	case d.Kind.Of() != KindValue && d.Kind.Of() != KindClassification:
		return invalid("provider: fact %q has unknown kind %q", d.Name, d.Kind)
	case d.Kind.Of() == KindClassification && d.Type != TypeIdentifier:
		return invalid("provider: classification fact %q is an identifier whose value is a data class", d.Name)
	case CELName(d.Name) == CELName(NameClassification) && d.Kind.Of() != KindClassification:
		return invalid("provider: %q is a classification and needs the classification kind", d.Name)
	case reservedFor(d.Name) && !p.Builtin:
		return invalid("provider: %q is written only by PantherClaw's own signals receiver", d.Name)
	}
	return nil
}

// checkProvenance checks an observation's source and method: both or
// neither, and both for a classification (HR-435).
func checkProvenance(d Declaration, o Observation) error {
	switch {
	case (o.Source == "") != (o.Method == ""):
		return invalid("%s: a source and a method go together", o.Name)
	case strings.ContainsFunc(o.Source, lineBreak) || len(o.Source) > MaxSourceLen || (o.Source != "" && cleanSource(o.Source) == ""):
		return invalid("%s: the source is one line of at most %d characters", o.Name, MaxSourceLen)
	case o.Method != "" && !slices.Contains(Methods, o.Method):
		return invalid("%s: the method is one of %v", o.Name, Methods)
	case d.Kind.Of() == KindClassification && o.Source == "":
		return invalid("%s: a classification needs its provenance, a source and a method", o.Name)
	}
	return nil
}

// checkClass checks a classification's value: one of the data classes.
func checkClass(d Declaration, v Value) error {
	if d.Kind.Of() == KindClassification && !slices.Contains(defs.DataClasses, v.Str) {
		return invalid("%s: a classification is one of %v", d.Name, defs.DataClasses)
	}
	return nil
}

// Class returns a classification fact's data class, or "" when f is not
// one (its value is not a data class).
func (f Fact) Class() string {
	if f.Value.Type != TypeIdentifier || !slices.Contains(defs.DataClasses, f.Value.Str) {
		return ""
	}
	return f.Value.Str
}

// cleanSource strips from a fact's source the characters the approvals
// untrusted-text cleaner removes (approvals/domain.Clean, HR-034, HR-102):
// controls, format and bidi characters and invisible marks. Newlines are
// refused before (checkProvenance).
func cleanSource(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == utf8.RuneError, unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Bidi_Control, r),
			(r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) || r == 0x034F:
			return -1
		}
		return r
	}, s)
}

// lineBreak reports a carriage return, line feed, line or paragraph
// separator.
func lineBreak(r rune) bool { return r == 0x0a || r == 0x0d || r == 0x2028 || r == 0x2029 }
