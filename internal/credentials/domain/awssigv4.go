// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"net/url"
	"regexp"
)

// KindAWSSigV4 is an AWS credential used only through short-lived sessions
// (G0 M20 D254, HR-525): the sealed base access key signs nothing but an
// sts:AssumeRole of one role, with a session policy narrowed to the one
// operation dispatched and the shortest duration AWS allows (15 minutes).
// The target request is signed with that session's temporary key, which is
// dropped when the dispatch ends; the base key never reaches the target.
const KindAWSSigV4 = "aws_sigv4"

// AWS session credentials are placed as a SigV4 "Authorization:
// AWS4-HMAC-SHA256 ..." header.
const (
	AWSSigV4Header = "Authorization"
	AWSSigV4Scheme = "AWS4-HMAC-SHA256"
)

// AWSSessionSeconds is every session's duration: AWS's minimum for
// AssumeRole, so at most 15 minutes (HR-525).
const AWSSessionSeconds = 900

// ErrAWSSigV4 reports an AWS credential that cannot be used.
var ErrAWSSigV4 = errors.New("credentials: not an AWS SigV4 credential")

// AWSSigV4 is the sealed content of an AWS credential: the base access key,
// the role every session assumes (and its external id, when the role's
// trust policy requires one), the STS endpoint and signing region, and the
// signing region and service of the connection's own endpoint. Every host
// it reaches, STS included, must be bound by the seal (HR-060). The opener
// clears SecretAccessKey (Clear) once AssumeRole is signed.
type AWSSigV4 struct {
	V               int    `json:"v"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey []byte `json:"secret_access_key"`
	RoleARN         string `json:"role_arn"`
	ExternalID      string `json:"external_id,omitzero"`
	STSURL          string `json:"sts_url"`
	STSRegion       string `json:"sts_region"`
	Region          string `json:"region"`
	Service         string `json:"service"`
}

var (
	accessKeyRe  = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
	awsSecretRe  = regexp.MustCompile(`^[\x21-\x7e]{16,128}$`)
	roleARNRe    = regexp.MustCompile(`^arn:aws(-[a-z]+){0,2}:iam::(?P<account>[0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	externalIDRe = regexp.MustCompile(`^[A-Za-z0-9+=,.@:/_-]{2,}$`)
	regionRe     = regexp.MustCompile(`^[a-z]{2}(-[a-z]+){1,2}-[0-9]{1,2}$`)
	serviceRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
)

// Account is the 12-digit account of the role every session assumes.
func (a AWSSigV4) Account() string {
	m := roleARNRe.FindStringSubmatch(a.RoleARN)
	if m == nil {
		return ""
	}
	return m[roleARNRe.SubexpIndex("account")]
}

// STS returns the parsed STS endpoint: https (http only for a loopback
// simulator, by the connection's own egress rules), a host, and nothing
// else.
func (a AWSSigV4) STS() (*url.URL, error) {
	u, err := url.Parse(a.STSURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return nil, ErrAWSSigV4
	}
	return u, nil
}

// Validate checks every field.
func (a AWSSigV4) Validate() error {
	if a.V != 1 || !accessKeyRe.MatchString(a.AccessKeyID) || !awsSecretRe.Match(a.SecretAccessKey) || a.Account() == "" ||
		(a.ExternalID != "" && (len(a.ExternalID) > 1224 || !externalIDRe.MatchString(a.ExternalID))) || !regionRe.MatchString(a.STSRegion) ||
		!regionRe.MatchString(a.Region) || !serviceRe.MatchString(a.Service) || len(a.RoleARN) > 2048 {
		return ErrAWSSigV4
	}
	_, err := a.STS()
	return err
}

// Encode returns the plaintext to seal.
func (a AWSSigV4) Encode() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(a, json.Deterministic(true))
}

// DecodeAWSSigV4 decodes and validates an opened AWS credential.
func DecodeAWSSigV4(plain []byte) (AWSSigV4, error) {
	var a AWSSigV4
	if err := json.UnmarshalRead(bytes.NewReader(plain), &a, json.RejectUnknownMembers(true)); err != nil {
		return AWSSigV4{}, ErrAWSSigV4
	}
	return a, a.Validate()
}

// Clear overwrites the base secret's bytes.
func (a *AWSSigV4) Clear() { clear(a.SecretAccessKey) }
