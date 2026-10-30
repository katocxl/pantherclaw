// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the rules of PantherClaw-hosted gateways (G0 M19
// D203, ADR-0041): one gateway process per org on a shared host, on the
// Team edition and above, within the plan's quota.
package domain

import (
	"regexp"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/hosting/profile"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// States of a hosted gateway record (migration 00229).
const (
	StateRequested      = "REQUESTED"
	StateProvisioned    = "PROVISIONED"
	StateEnrolled       = "ENROLLED"
	StateRunning        = "RUNNING"
	StateDeprovisioning = "DEPROVISIONING"
	StateDeprovisioned  = "DEPROVISIONED"
	StateFailed         = "FAILED"
)

// Host states (migration 00228).
const (
	HostActive   = "ACTIVE"
	HostDraining = "DRAINING"
	HostRetired  = "RETIRED"
)

// Errors.
var (
	ErrEdition = pcerr.New(pcerr.FailedPrecondition, "HOSTED_GATEWAY_EDITION",
		"PantherClaw-hosted gateways need the Team edition or above")
	ErrSlug = pcerr.New(pcerr.InvalidArgument, "HOSTED_GATEWAY_SLUG",
		"the slug must be a DNS label: lowercase letters, digits and inner hyphens, at most 63")
	// ErrOneOnly: an org has at most one live hosted gateway (HR-499).
	ErrOneOnly  = pcerr.New(pcerr.AlreadyExists, "HOSTED_GATEWAY_EXISTS", "the org already has a hosted gateway")
	ErrQuota    = pcerr.New(pcerr.ResourceExhausted, "HOSTED_GATEWAY_QUOTA", "the requested resources exceed the plan's quota")
	ErrNotFound = pcerr.New(pcerr.NotFound, "HOSTED_GATEWAY_NOT_FOUND", "hosted gateway not found")
	// ErrNoCapacity: no active host has room for it; the request stays queued.
	ErrNoCapacity = pcerr.New(pcerr.Unavailable, "HOSTING_NO_CAPACITY", "no hosting host can take it")
	// ErrSlugTaken: another hosted gateway holds the slug (D222).
	ErrSlugTaken = pcerr.New(pcerr.AlreadyExists, "SLUG_TAKEN", "another hosted gateway uses this slug")
)

var slugRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidSlug reports whether s can name a hosted gateway: one DNS label.
func ValidSlug(s string) bool { return slugRE.MatchString(s) }

// Allowed reports whether the edition may request a hosted gateway: Team
// and above (PN-010.4, D212). Only a request is gated.
func Allowed(e billing.Entitlements) bool { return e.HostedGateways() }

// Quota is the most one org's hosted gateway may ask for on its edition
// (T-218): the Team edition gets the default profile, larger editions up
// to the profile's ceilings.
func Quota(e billing.Entitlements) profile.Limits {
	switch e.Edition { //nolint:exhaustive // every other edition has no quota
	case billing.Business, billing.Enterprise:
		return profile.Ceilings
	case billing.Team:
		return profile.DefaultLimits
	}
	return profile.Limits{}
}

// Fit fills unset limits with the defaults and checks them against the
// edition's quota.
func Fit(e billing.Entitlements, asked profile.Limits) (profile.Limits, error) {
	if !Allowed(e) {
		return profile.Limits{}, ErrEdition
	}
	q, d := Quota(e), profile.DefaultLimits
	out := asked
	if out.MilliCPUs == 0 {
		out.MilliCPUs = min(d.MilliCPUs, q.MilliCPUs)
	}
	if out.MemoryMiB == 0 {
		out.MemoryMiB = min(d.MemoryMiB, q.MemoryMiB)
	}
	if out.PIDs == 0 {
		out.PIDs = min(d.PIDs, q.PIDs)
	}
	if out.MilliCPUs < 100 || out.MemoryMiB < 128 || out.PIDs < 32 ||
		out.MilliCPUs > q.MilliCPUs || out.MemoryMiB > q.MemoryMiB || out.PIDs > q.PIDs {
		return profile.Limits{}, ErrQuota
	}
	return out, nil
}

// Hostname is the name agents reach an org's hosted gateway at.
func Hostname(slug, domain string) string { return slug + ".gw." + domain }
