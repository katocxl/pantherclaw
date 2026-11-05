// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package celenv

import (
	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// urlLibrary adds the url functions of G0 M33 D975, each returning ""
// for an input that is not an absolute http or https URL (an empty
// required value then fails the mapping, HR-748):
//
//   - normurl(string) string: the one spelling (actionir.NormalizeURL);
//   - urlhost(string) string: the host without port, IPv6 in brackets;
//   - urlquery(string) string: the raw query as sent.
func urlLibrary() []cel.EnvOption {
	fn := func(name string, f func(string) string) cel.EnvOption {
		return cel.Function(name, cel.Overload(name+"_string", []*cel.Type{cel.StringType}, cel.StringType,
			cel.UnaryBinding(func(v ref.Val) ref.Val {
				s, ok := v.(types.String)
				if !ok {
					return types.MaybeNoSuchOverloadErr(v)
				}
				return types.String(f(string(s)))
			})))
	}
	return []cel.EnvOption{
		fn("normurl", actionir.NormalizeURL),
		fn("urlhost", actionir.URLHost),
		fn("urlquery", actionir.URLQuery),
	}
}
