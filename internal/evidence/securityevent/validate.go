// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package securityevent

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Validate rejects malformed or unbounded machine projections before
// storage, emission or replay. Handler availability is checked by restore.
func Validate(e Event) error {
	dir, typ, ok := Rule(e.Kind)
	if !ok {
		return fmt.Errorf("unknown security kind %q", e.Kind)
	}
	validType := e.Object.Type == typ || typ == "session" && (e.Object.Type == "browser_session" || e.Object.Type == "cli_session")
	if e.Direction != dir || !validType {
		return fmt.Errorf("security event: direction/object disagrees with %s", e.Kind)
	}
	if e.Timestamp.IsZero() || e.Org.IsZero() || e.LedgerSeq < 1 || e.Object.ID == "" || len(e.Object.ID) > 256 || e.Actor.Type == "" || len(e.Actor.Type) > 32 || e.Actor.ID == "" || len(e.Actor.ID) > 256 {
		return errors.New("security event: missing or oversized fields")
	}
	if e.Kind == "org.deleted" || e.Kind == "account.deleted" {
		if e.Org != ids.PlatformOrg || len(e.RecordDigest) != 64 {
			return errors.New("security event: deletion requires platform ledger and record digest")
		}
		if _, err := hex.DecodeString(e.RecordDigest); err != nil {
			return errors.New("security event: invalid deletion digest")
		}
	} else if e.RecordDigest != "" {
		return errors.New("security event: unexpected record digest")
	}
	if e.Kind == "org.deletion_started" || e.Kind == "account.deletion_started" {
		if e.Org != ids.PlatformOrg || len(e.JournalDigest) != 64 || (e.Kind == "org.deletion_started" && e.RequestID.IsZero()) || (e.Kind == "account.deletion_started" && !e.RequestID.IsZero()) {
			return errors.New("security event: invalid deletion intent provenance")
		}
		if _, err := hex.DecodeString(e.JournalDigest); err != nil {
			return errors.New("security event: invalid journal digest")
		}
	} else if !e.RequestID.IsZero() || e.JournalDigest != "" {
		return errors.New("security event: unexpected deletion intent metadata")
	}
	return validateObject(e)
}

var machineID = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

var serverName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// validateServer bounds a revoke's spec. The catalogue checks its meaning when
// a restore uses it.
func validateServer(e Event) error {
	s := e.McpServer
	if e.Kind != "mcp.catalog.server_revoked" {
		return errors.New("security event: unexpected server spec")
	}
	if !serverName.MatchString(s.Name) || (s.Transport != "http" && s.Transport != "stdio" && s.Transport != "container") {
		return errors.New("security event: invalid server spec")
	}
	if len(s.PackageRef) > 256 || len(s.URLHost) > 261 || len(s.URLPathPrefix) > 512 || len(s.ImageDigest) > 71 {
		return errors.New("security event: oversized server spec")
	}
	if s.PackageRef == "" && s.URLHost == "" && s.ImageDigest == "" {
		return errors.New("security event: a server spec names nothing")
	}
	return nil
}

func validateObject(e Event) error {
	if e.Kind == "security.kill_switch_engaged" && e.Object.ID != e.Org.String() {
		return errors.New("restore: kill switch object is another organization")
	}
	if e.Kind == "package.signing_key.revoked" {
		if e.RevocationReason != "ROTATED" && e.RevocationReason != "COMPROMISED" {
			return errors.New("restore: invalid package key revocation reason")
		}
	} else if e.RevocationReason != "" {
		return errors.New("restore: unexpected revocation reason")
	}
	switch e.Object.Type {
	case "signing_key", "package_signing_key":
		if !machineID.MatchString(e.Object.ID) {
			return errors.New("restore: invalid signing key id")
		}
	case "sealed_credential":
		conn, version, ok := strings.Cut(e.Object.ID, "/")
		if !ok {
			return errors.New("restore: invalid sealed credential id")
		}
		if id, err := ids.ParseUUID(conn); err != nil || id.IsZero() {
			return errors.New("restore: invalid connection id")
		}
		v, err := strconv.ParseInt(version, 10, 32)
		if err != nil || v < 0 || v == 0 && e.Kind != "response.credential_revoked" || strconv.FormatInt(v, 10) != version {
			return errors.New("restore: invalid credential version")
		}
	default:
		if id, err := ids.ParseUUID(e.Object.ID); err != nil || id.IsZero() {
			return fmt.Errorf("restore: invalid %s id", e.Object.Type)
		}
	}
	if e.McpServer != nil {
		if err := validateServer(e); err != nil {
			return err
		}
	}
	if e.Kind != "response.contain" {
		if e.Containment != nil {
			return errors.New("restore: unexpected containment metadata")
		}
		return nil
	}
	c := e.Containment
	if c == nil || c.ActionID.IsZero() || c.ControlID.IsZero() || c.ControlID.String() != e.Object.ID || len(c.ScopeID) > 300 || len(c.Operation) > 200 {
		return errors.New("restore: missing or invalid containment metadata")
	}
	if c.Source != "PERSON" && c.Source != "SOAR" && c.Source != "PLAYBOOK" {
		return errors.New("restore: invalid containment source")
	}
	switch c.ScopeType {
	case "agent", "run", "grant", "connection", "resource", "principal":
	default:
		return errors.New("security event: invalid containment scope type")
	}
	if c.ScopeID == "" {
		return errors.New("security event: missing containment scope")
	}
	if c.Server != "" {
		if id, err := ids.ParseUUID(c.Server); err != nil || id.IsZero() || c.ScopeType != "connection" {
			return errors.New("security event: invalid containment server")
		}
	}
	switch c.Control {
	case "DENY_ALL", "HOLD_WRITES":
		if c.Operation != "" {
			return errors.New("security event: unexpected operation")
		}
	case "DENY_OPERATION":
		if c.Operation == "" {
			return errors.New("security event: missing operation")
		}
	default:
		return errors.New("security event: invalid control")
	}
	return nil
}
