// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"math"
)

// TypeFloatArray is a list of finite numbers, such as an embedding (G0 M30
// D927): at least one and at most MaxItems values. The gateway binds it as
// a query parameter and never sends it from a template; policies cannot see
// it.
const TypeFloatArray ParamType = "float_array"

// MaxFloatItems bounds a float_array's declared max_items.
const MaxFloatItems = 16000

// decodeFloats strictly decodes a float_array: a JSON list of numbers, none
// missing, none infinite or NaN, within max items.
func (p ParamSpec) decodeFloats(raw jsontext.Value) ([]float64, error) {
	var fs []float64
	if err := json.Unmarshal(raw, &fs); err != nil || fs == nil {
		return nil, fmt.Errorf("must be a list of numbers")
	}
	return fs, p.floats(fs)
}

func (p ParamSpec) floats(fs []float64) error {
	if len(fs) == 0 || len(fs) > p.MaxItems {
		return fmt.Errorf("must hold 1..%d numbers", p.MaxItems)
	}
	for _, f := range fs {
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("must hold finite numbers only")
		}
	}
	return nil
}
