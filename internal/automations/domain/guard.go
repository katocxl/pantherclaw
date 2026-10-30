// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"sync"

	"cel.dev/cel-go/cel"

	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

// GuardVariables are the variables a step, branch or case guard may read
// (D2, D301).
var GuardVariables = []celenv.Variable{
	{Name: "trigger", Type: cel.MapType(cel.StringType, cel.DynType)},
	{Name: "steps", Type: cel.MapType(cel.StringType, cel.DynType)},
}

var guardEnv = sync.OnceValues(func() (*celenv.Env, error) {
	return celenv.New(celenv.DefaultLimits, nil, GuardVariables...)
})

// CompileGuard checks a guard expression.
func CompileGuard(src string) error {
	env, err := guardEnv()
	if err != nil {
		return err
	}
	_, err = env.Compile(src, cel.BoolType)
	return err
}
