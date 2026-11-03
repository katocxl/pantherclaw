// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

// Policy rules see how the Authority verified the workload behind an action
// as `workload` (G0 M26 D402, HR-627): `workload.proof` is "pap" for a
// PAP/1 proof of possession and "bearer" for an MCP access token, and
// `workload.attestation` is the verified attestation level. Both come from
// the Authority's own verification, never from the request; bearer proof is
// always level 0.
const workloadType = "pc.Workload"

// Proof kinds of `workload.proof`.
const (
	ProofPAP    = "pap"
	ProofBearer = "bearer"
)

// Workload is the verified workload of an action.
type Workload struct {
	// Proof is ProofPAP or ProofBearer; "" is ProofPAP.
	Proof       string
	Attestation int
}

// WorkloadSchema is the typed shape of `workload`.
var WorkloadSchema = celenv.Schema{workloadType: {Name: workloadType, Fields: map[string]celenv.Field{
	"proof":       {Type: cel.StringType},
	"attestation": {Type: cel.IntType},
}}}

// WorkloadVariable declares `workload`.
var WorkloadVariable = celenv.Variable{Name: "workload", Type: types.NewObjectType(workloadType)}

// WorkloadRecord builds the runtime value of `workload`; nil is a PAP/1
// workload at level 0.
func WorkloadRecord(w *Workload) *celenv.Record {
	proof, level := ProofPAP, 0
	if w != nil {
		if w.Proof != "" {
			proof = w.Proof
		}
		level = w.Attestation
	}
	return &celenv.Record{TypeName: workloadType, Fields: map[string]ref.Val{
		"proof": types.String(proof), "attestation": types.Int(level),
	}}
}
