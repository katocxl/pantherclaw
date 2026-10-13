// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"
	"regexp"
	"slices"
	"strings"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	rapp "github.com/katocxl/pantherclaw/internal/releases/app"
	rdomain "github.com/katocxl/pantherclaw/internal/releases/domain"
)

// repositoryRe is a consequence target that names a repository, whose own
// change window decides before its environment's (00082).
var repositoryRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}/[a-z0-9._-]{1,100}$`)

// windows checks, before a permit consumes an approval with a window
// requirement, that every environment the action's predicted or unknown
// consequences reach is inside an active change window now, by the
// database clock (G0 M8, HR-207). A freeze overrides a window, and no
// configured window is no window. A consequence that names no environment
// (an unknown one) is in no window, and neither is an action without a
// consequence: the approval then waits, unconsumed, until it expires.
func windows(ctx context.Context, q *dbq.Queries, org ids.OrgID, ev *pipeline.Evaluation) error {
	h := ev.Hold
	if h == nil || !slices.ContainsFunc(h.Requirements, func(r apdomain.Requirement) bool { return r.Window }) {
		return nil
	}
	var closed []string
	reached := false
	for _, c := range ev.Consequences {
		if c.Err != nil || (c.State != consequences.Predicted && c.State != consequences.Unknown) {
			continue
		}
		reached = true
		if len(c.Environments) == 0 {
			closed = append(closed, c.Operation+" on "+c.Target.ID+" reaches no known environment")
			continue
		}
		repo := ""
		if repositoryRe.MatchString(c.Target.ID) {
			repo = c.Target.ID
		}
		for _, env := range c.Environments {
			d, err := rapp.Decide(ctx, q, org, env, repo)
			if err != nil {
				return err
			}
			if d.State != rdomain.Open {
				closed = append(closed, env+" is "+string(d.State))
			}
		}
	}
	if !reached {
		closed = append(closed, "no consequence of the action reaches an environment")
	}
	if len(closed) > 0 {
		return &finalize.WindowClosedError{Detail: "a release approval counts only inside a change window: " + strings.Join(closed, "; ")}
	}
	return nil
}
