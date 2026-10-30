// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import "github.com/katocxl/pantherclaw/internal/authority/pipeline"

// WithExternalCheck gives the decision pipeline the org's external policy
// checks (G0 M16 D81): asked after the policy rules, restrict only.
func (s *Service) WithExternalCheck(c pipeline.ExternalCheck) *Service {
	if s.decider != nil && s.decider.Pipeline != nil {
		s.decider.Pipeline.External = c
	}
	return s
}
