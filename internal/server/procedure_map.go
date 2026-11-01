// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

// ProcedureInfo is what the server enforces on one procedure: the permission
// its proto declares and its plan-gate class. A procedure that never reaches
// the plan gate has class "unknown".
type ProcedureInfo struct {
	Permission string `json:"permission"`
	Class      string `json:"class"`
}

// ProcedureMap is the merged procedure table, side maps included (G0 M22 D9).
// It reads the tables after every init has run, so tools that mirror them
// never have to parse Go source.
func ProcedureMap() map[string]ProcedureInfo {
	out := make(map[string]ProcedureInfo, len(procedurePermissions))
	for proc, perm := range procedurePermissions {
		out[proc] = ProcedureInfo{Permission: string(perm), Class: procedureClass(proc).String()}
	}
	return out
}
