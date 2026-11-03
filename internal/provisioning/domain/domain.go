// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the pure rules of provisioning (G0 M26 D405, D406,
// D409): which roles a group may carry, and what a SAML connection may hold.
package domain

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ErrRoleNotMappable refuses a group mapping of a role that stays in
// PantherClaw.
var ErrRoleNotMappable = pcerr.New(pcerr.InvalidArgument, "ROLE_NOT_MAPPABLE",
	"this role can't be given by a group: it stays bound in PantherClaw")

// keptInPantherClaw are the roles no group may carry by name. A group change
// takes effect with no second person (R-08), so Emergency Responder stays
// here though it holds no role.bind (D409).
var keptInPantherClaw = []td.RoleName{td.RoleOrgAdmin, td.RoleSecurityAdmin, td.RoleScopeAdmin, td.RoleEmergency}

// roleMappable is the rule: decided by what a role can do, so a new role that
// can bind others is refused without anyone remembering to list it.
func roleMappable(r td.Role) bool {
	return !r.Has(td.PermRoleBind) && !slices.Contains(keptInPantherClaw, r.Name)
}

// UnmappableRoles are the roles the rule refuses that a person could hold.
// The checks of migration 00292 must list every one of them.
func UnmappableRoles() []td.RoleName {
	var out []td.RoleName
	for _, r := range td.Roles() {
		if !roleMappable(r) {
			out = append(out, r.Name)
		}
	}
	return out
}

// CheckMappable reports whether a group may carry role at scope type t: the
// role can be bound to a person there and does not stay in PantherClaw.
func CheckMappable(role td.RoleName, t td.ScopeType) error {
	r, err := td.CheckBindable(role, td.KindUser, t)
	if err != nil {
		return err
	}
	if !roleMappable(r) {
		return ErrRoleNotMappable
	}
	return nil
}

// Subject attributes of a SCIM token.
const (
	SubjectUserName   = "userName"
	SubjectExternalID = "externalId"
)

// Token and connection states.
const (
	StatePending  = "PENDING"
	StateActive   = "ACTIVE"
	StateRevoked  = "REVOKED"
	StateDisabled = "DISABLED"
	StateLapsed   = "LAPSED"
)

// Bounds.
const (
	// MaxTokenDays bounds a SCIM token's life.
	MaxTokenDays = 366
	// MaxConnections bounds an org's SAML connections.
	MaxConnections = 16
	maxEntityID    = 500
	maxSSOURL      = 2048
	maxCerts       = 4
	minRSABits     = 2048
)

// IssuerPrefix keeps a SAML entity id apart from every OpenID issuer.
const IssuerPrefix = "saml:"

// ProviderPrefix keeps a SAML sign-in request apart from every OpenID
// provider's.
const ProviderPrefix = "saml-"

var (
	namePattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,25}[a-z0-9])?$`)
	tokenPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidTokenName reports whether name may name a SCIM token.
func ValidTokenName(name string) bool { return tokenPattern.MatchString(name) }

// Fingerprint is the SHA-256 of a base64 DER certificate, in hex, or
// "invalid".
func Fingerprint(cert string) string {
	der, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return "invalid"
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ErrInvalidConnection refuses a connection's settings.
var ErrInvalidConnection = pcerr.New(pcerr.InvalidArgument, "SAML_CONNECTION_INVALID", "the SAML connection is not valid")

// Connection are a SAML connection's settings.
type Connection struct {
	Name, EntityID, SSOURL string
	// Certificates are base64 DER X.509 certificates.
	Certificates []string
}

// CheckCertificates reports whether every certificate parses, has a key a
// signature can be trusted with, and is valid at now. PEM armour is not
// accepted: the stored form is one line of base64.
func CheckCertificates(certs []string, now time.Time) error {
	if len(certs) == 0 || len(certs) > maxCerts {
		return fmt.Errorf("a connection needs 1-%d certificates", maxCerts)
	}
	for i, c := range certs {
		der, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return fmt.Errorf("certificate %d is not base64 DER", i+1)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("certificate %d does not parse", i+1)
		}
		switch k := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			if k.N.BitLen() < minRSABits {
				return fmt.Errorf("certificate %d has an RSA key under %d bits", i+1, minRSABits)
			}
		case *ecdsa.PublicKey:
		default:
			return fmt.Errorf("certificate %d has neither an RSA nor an ECDSA key", i+1)
		}
		if now.After(cert.NotAfter) {
			return fmt.Errorf("certificate %d has expired", i+1)
		}
	}
	return nil
}

// Validate checks settings; checkURL is the core's check of a public HTTPS
// URL. Certificates are checked at now.
func (c Connection) Validate(checkURL func(string) error, now time.Time) error {
	var errs []error
	if !namePattern.MatchString(c.Name) {
		errs = append(errs, errors.New("name must be 1-27 lowercase letters, digits or hyphens"))
	}
	if c.EntityID == "" || len(c.EntityID) > maxEntityID || strings.ContainsAny(c.EntityID, " \t\r\n") {
		errs = append(errs, fmt.Errorf("the entity id is 1-%d characters without spaces", maxEntityID))
	}
	if len(c.SSOURL) > maxSSOURL {
		errs = append(errs, fmt.Errorf("the sign-in URL is at most %d characters", maxSSOURL))
	} else if err := checkURL(c.SSOURL); err != nil {
		errs = append(errs, fmt.Errorf("sign-in URL: %w", err))
	}
	if err := CheckCertificates(c.Certificates, now); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return pcerr.New(pcerr.InvalidArgument, ErrInvalidConnection.Reason(), err.Error())
	}
	return nil
}
