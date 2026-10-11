// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packbuild_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/packbuild"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// TestHR056_PackJobsCarryIDsOnly: the build and expiry jobs register (their
// arguments are typed ids only), and a build job names an org and a pack.
func TestHR056_PackJobsCarryIDsOnly(t *testing.T) {
	if err := packbuild.Register(jobs.NewRegistry(), &packbuild.Service{}); err != nil {
		t.Fatal(err)
	}
	org, pack := ids.New[ids.Org](), ids.NewV7()
	args, err := packbuild.NewBuildArgs(org, pack)
	if err != nil || args.Org != org || args.Pack.UUID() != pack {
		t.Fatalf("NewBuildArgs = %+v, %v", args, err)
	}
	if _, err := packbuild.NewBuildArgs(org, ids.UUID{}); err == nil {
		t.Fatal("a nil pack id was accepted")
	}
}
