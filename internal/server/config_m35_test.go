// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"strings"
	"testing"
)

func anchoringFile() AnchoringConfig {
	return AnchoringConfig{
		Enabled: true,
		Rekor:   RekorConfig{URL: "https://log.example", PublicKeyFile: "rekor.pem", Origin: "log.example"},
		TSA:     TSAConfig{URL: "https://timestamp.example/api/v1/timestamp", CertChainFile: "tsa.pem"},
	}
}

// TestHR781_AnchoringTrustIsFileOrTUF: the log key comes from the files or
// from TUF, and setting both is refused.
func TestHR781_AnchoringTrustIsFileOrTUF(t *testing.T) {
	if err := firstErr(anchoringFile().validate()); err != nil {
		t.Fatalf("file trust: %v", err)
	}
	tuf := anchoringFile()
	tuf.Trust = anchoringTrustTUF
	tuf.Rekor.PublicKeyFile = ""
	tuf.TSA.CertChainFile = ""
	if err := firstErr(tuf.validate()); err != nil {
		t.Fatalf("tuf trust: %v", err)
	}
	both := anchoringFile()
	both.Trust = anchoringTrustTUF
	err := firstErr(both.validate())
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("file and tuf together: %v", err)
	}
}

func firstErr(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return errs[0]
}
