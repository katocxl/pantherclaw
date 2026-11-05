// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math"
)

// TypeFloatArray is a list of finite numbers, such as an embedding (G0 M30
// D927): at least one and at most MaxItems values. The gateway binds it as
// a query parameter and never sends it from a template; policies cannot see
// it.
//
// In an ActionIR a float_array is one canonical string, never a JSON
// number (HR-101, G0 M30 D1211): padded standard base64 of the values as
// little-endian IEEE 754 float32s. A tool call's numbers are read only
// where the mapping extracts a float_array, and become that string
// (mapping.DecodeInput).
const TypeFloatArray ParamType = "float_array"

// MaxFloatItems bounds a float_array's declared max_items.
const MaxFloatItems = 16000

// ErrFloatArray reports values that have no canonical float_array form.
var ErrFloatArray = fmt.Errorf("a float_array holds 1..%d finite numbers within float32 range", MaxFloatItems)

// EncodeFloat32s returns the canonical ActionIR form of fs: each value must
// be finite and within float32 range, and is rounded to the nearest float32.
func EncodeFloat32s(fs []float64) (string, error) {
	if len(fs) == 0 || len(fs) > MaxFloatItems {
		return "", ErrFloatArray
	}
	b := make([]byte, 4*len(fs))
	for i, f := range fs {
		if math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > math.MaxFloat32 {
			return "", ErrFloatArray
		}
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(float32(f)))
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// DecodeFloat32s strictly reads the canonical form: padded standard base64
// whose re-encoding is the same string, a whole number of float32s, every
// one finite.
func DecodeFloat32s(s string) ([]float64, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) == 0 || len(b)%4 != 0 || len(b)/4 > MaxFloatItems || base64.StdEncoding.EncodeToString(b) != s {
		return nil, ErrFloatArray
	}
	out := make([]float64, len(b)/4)
	for i := range out {
		f := float64(math.Float32frombits(binary.LittleEndian.Uint32(b[4*i:])))
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, ErrFloatArray
		}
		out[i] = f
	}
	return out, nil
}

// decodeFloats strictly decodes a float_array from its ActionIR form, the
// canonical string, within max items.
func (p ParamSpec) decodeFloats(raw jsontext.Value) ([]float64, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, errors.New("must be the canonical float_array string")
	}
	fs, err := DecodeFloat32s(s)
	if err != nil {
		return nil, err
	}
	return fs, p.floats(fs)
}

func (p ParamSpec) floats(fs []float64) error {
	if len(fs) == 0 || len(fs) > p.MaxItems {
		return fmt.Errorf("must hold 1..%d numbers", p.MaxItems)
	}
	for _, f := range fs {
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return errors.New("must hold finite numbers only")
		}
	}
	return nil
}
