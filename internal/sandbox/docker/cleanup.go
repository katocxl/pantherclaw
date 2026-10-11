// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package docker

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// LabelSession is the label every sandbox and connector resource carries,
// with its session or connector id as the value.
const LabelSession = "org.pantherclaw.sandbox.session"

var (
	idRE    = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
	valueRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// RemoveLabelled removes every container, then every network and volume,
// that carries LabelSession=session: what one session created, also after
// an interruption. Nothing without that exact label is touched; the engine
// is shared.
func (c *Client) RemoveLabelled(ctx context.Context, session string) error {
	if !valueRE.MatchString(session) {
		return fmt.Errorf("%w: session %q", ErrInvalid, session)
	}
	filter := "label=" + LabelSession + "=" + session
	var errs []error
	for _, kind := range [][2][]string{
		{{"ps", "--all", "--quiet", "--no-trunc", "--filter", filter}, {"rm", "--force", "--volumes"}},
		{{"network", "ls", "--quiet", "--no-trunc", "--filter", filter}, {"network", "rm"}},
		{{"volume", "ls", "--quiet", "--filter", filter}, {"volume", "rm", "--force"}},
	} {
		out, err := c.r.Run(ctx, kind[0]...)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, id := range strings.Fields(string(out)) {
			// Volume names are ours (pc-…); container and network ids are hex.
			if !idRE.MatchString(id) && checkName(id) != nil {
				errs = append(errs, fmt.Errorf("docker: unexpected id %q", id))
				continue
			}
			if _, err := c.r.Run(ctx, append(kind[1], id)...); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
