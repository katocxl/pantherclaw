// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

// WithGrantPage is s reading a connection's grants n at a time for its
// health, so a test reaches past the first page with a few grants.
func (s *Service) WithGrantPage(n int32) *Service {
	c := *s
	c.grantsPage = n
	return &c
}
