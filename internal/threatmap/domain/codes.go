// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"strings"
)

// Snapshot codes (D719): one string "P D R T S" per matrix technique.
var (
	laneCodes = map[LaneState]string{
		LaneEvidenced: "E", LanePartial: "P", LaneGap: "G", LaneStated: "S", LaneNoneShipped: "N",
	}
	testCodes   = map[TestState]string{TestPassed: "P", TestFailed: "F", TestStale: "S", TestNotRun: "N"}
	statusCodes = map[Status]string{StatusEvidenced: "E", StatusPartial: "P", StatusGap: "G", StatusOutside: "O"}
)

func decode[K comparable](codes map[K]string, c string) (K, bool) {
	for k, v := range codes {
		if v == c {
			return k, true
		}
	}
	var zero K
	return zero, false
}

// Code is a technique's snapshot code.
func (t Technique) Code() string {
	return strings.Join([]string{
		laneCodes[t.Prevent.State], laneCodes[t.Detect.State], laneCodes[t.Respond.State],
		testCodes[t.Test.State], statusCodes[t.Status],
	}, " ")
}

// Codes are the map's snapshot codes by technique id.
func (m Map) Codes() map[string]string {
	out := make(map[string]string, len(m.Techniques))
	for _, t := range m.Techniques {
		out[t.ID] = t.Code()
	}
	return out
}

// Decoded is one snapshot code read back.
type Decoded struct {
	Prevent, Detect, Respond LaneState
	Test                     TestState
	Status                   Status
}

// Decode reads a snapshot code.
func Decode(code string) (Decoded, bool) {
	f := strings.Fields(code)
	if len(f) != 5 {
		return Decoded{}, false
	}
	var d Decoded
	var ok [5]bool
	d.Prevent, ok[0] = decode(laneCodes, f[0])
	d.Detect, ok[1] = decode(laneCodes, f[1])
	d.Respond, ok[2] = decode(laneCodes, f[2])
	d.Test, ok[3] = decode(testCodes, f[3])
	d.Status, ok[4] = decode(statusCodes, f[4])
	return d, ok == [5]bool{true, true, true, true, true}
}

// Drop is one lane that dropped between two snapshots.
type Drop struct {
	TechniqueID string `json:"technique_id"`
	Lane        Lane   `json:"lane"`
	From        string `json:"from"`
	To          string `json:"to"`
}

// Drops compares two snapshots' codes (D719): Prevent, Detect or Respond
// EVIDENCED to anything else, or Test PASSED to FAILED, is a drop.
// Techniques missing from either side are skipped. Sorted by technique, then
// lane.
func Drops(before, after map[string]string) []Drop {
	var out []Drop
	for id, a := range after {
		b, ok := before[id]
		if !ok {
			continue
		}
		db, okb := Decode(b)
		da, oka := Decode(a)
		if !okb || !oka {
			continue
		}
		for _, l := range []struct {
			lane     Lane
			from, to LaneState
		}{{LanePrevent, db.Prevent, da.Prevent}, {LaneDetect, db.Detect, da.Detect}, {LaneRespond, db.Respond, da.Respond}} {
			if l.from == LaneEvidenced && l.to != LaneEvidenced {
				out = append(out, Drop{TechniqueID: id, Lane: l.lane, From: string(l.from), To: string(l.to)})
			}
		}
		if db.Test == TestPassed && da.Test == TestFailed {
			out = append(out, Drop{TechniqueID: id, Lane: LaneTest, From: string(db.Test), To: string(da.Test)})
		}
	}
	slices.SortFunc(out, func(x, y Drop) int {
		if c := strings.Compare(x.TechniqueID, y.TechniqueID); c != 0 {
			return c
		}
		return strings.Compare(string(x.Lane), string(y.Lane))
	})
	return out
}

// StatusCounts counts the matrix techniques of a snapshot by status, each
// technique once.
func StatusCounts(codes map[string]string) map[Status]int {
	out := map[Status]int{}
	for _, c := range codes {
		if d, ok := Decode(c); ok {
			out[d.Status]++
		}
	}
	return out
}
