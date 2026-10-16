// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgengine

import (
	"encoding/json/v2"
	"fmt"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// ref is an evidence ref as stored: ids as text (ids.UUID has no text
// form).
type ref struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// EncodeRefs stores refs as JSON.
func EncodeRefs(rs []reflexdomain.EvidenceRef) ([]byte, error) {
	out := make([]ref, 0, len(rs))
	for _, r := range rs {
		out = append(out, ref{Kind: r.Kind, ID: r.ID.String()})
	}
	return json.Marshal(out, json.Deterministic(true))
}

// DecodeRefs reads stored refs.
func DecodeRefs(b []byte) ([]reflexdomain.EvidenceRef, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var in []ref
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, fmt.Errorf("pgengine: refs: %w", err)
	}
	out := make([]reflexdomain.EvidenceRef, 0, len(in))
	for _, r := range in {
		id, err := ids.ParseUUID(r.ID)
		if err != nil {
			return nil, fmt.Errorf("pgengine: ref id: %w", err)
		}
		out = append(out, reflexdomain.EvidenceRef{Kind: r.Kind, ID: id})
	}
	return out, nil
}

func encodeParams(p map[string]autodomain.Value) ([]byte, error) {
	if p == nil {
		p = map[string]autodomain.Value{}
	}
	return json.Marshal(p, json.Deterministic(true))
}

func decodeParams(b []byte) (map[string]autodomain.Value, error) {
	out := map[string]autodomain.Value{}
	if len(b) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("pgengine: params: %w", err)
	}
	return out, nil
}

func encodeSubjects(s []reflexdomain.Subject) ([]byte, error) {
	if s == nil {
		s = []reflexdomain.Subject{}
	}
	return json.Marshal(s, json.Deterministic(true))
}

func decodeSubjects(b []byte) ([]reflexdomain.Subject, error) {
	var out []reflexdomain.Subject
	if len(b) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("pgengine: subjects: %w", err)
	}
	return out, nil
}

func encodeOutput(o map[string]string) ([]byte, error) {
	if o == nil {
		o = map[string]string{}
	}
	return json.Marshal(o, json.Deterministic(true))
}

func decodeOutput(b []byte) (map[string]string, error) {
	out := map[string]string{}
	if len(b) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("pgengine: output: %w", err)
	}
	return out, nil
}

// DecodeParams reads an execution's stored typed parameters (inspector).
func DecodeParams(b []byte) (map[string]autodomain.Value, error) { return decodeParams(b) }
