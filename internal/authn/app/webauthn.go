// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// WebAuthn parameters (SB-2, G0 M5 part 1, HR-153..156).
const (
	// CeremonyTTL bounds a registration or assertion ceremony.
	CeremonyTTL = 5 * time.Minute
	// StepUpLifetime is how long a step-up counts on its session.
	StepUpLifetime = 5 * time.Minute
	// MaxCredentialsPerUser bounds one user's active credentials.
	MaxCredentialsPerUser = 20
	// minRSABits is the smallest accepted RSA key (RS256).
	minRSABits = 2048
	// maxResponseBytes bounds a ceremony response from the browser.
	maxResponseBytes = 64 << 10
)

// Ceremony purposes (webauthn_ceremonies.purpose).
const (
	purposeRegistration = "REGISTRATION"
	purposeStepUp       = "STEP_UP"
)

// allowedAlgorithms are the COSE algorithms accepted (HR-153): ES256,
// EdDSA and RS256 (Windows Hello), in the order offered to authenticators.
var allowedAlgorithms = []webauthncose.COSEAlgorithmIdentifier{webauthncose.AlgES256, webauthncose.AlgEdDSA, webauthncose.AlgRS256}

// WebAuthn errors.
var (
	// ErrRecentAuthRequired: adding or removing a key needs a provider
	// sign-in or a step-up at most 5 minutes old (HR-155).
	ErrRecentAuthRequired = errors.New("authn: a recent sign-in or step-up is required")
	// ErrNoCredentials: a step-up needs an active key.
	ErrNoCredentials = errors.New("authn: no active security key")
	// ErrCeremonyInvalid: the ceremony is unknown, expired, used, or another
	// session's or user's.
	ErrCeremonyInvalid = errors.New("authn: the security key request is invalid or has expired")
	// ErrWebAuthnFailed: the browser's response did not verify.
	ErrWebAuthnFailed = errors.New("authn: the security key response could not be verified")
	// ErrCredentialSuspended: the key's signature counter went backwards; the
	// key was suspended (HR-154).
	ErrCredentialSuspended = errors.New("authn: the security key was suspended (possible clone)")
	// ErrCredentialExists: the key is already registered in this org.
	ErrCredentialExists = errors.New("authn: this security key is already registered")
	// ErrTooManyCredentials: the user already has the maximum number of keys.
	ErrTooManyCredentials = errors.New("authn: too many security keys")
	// ErrCredentialNotFound: the id is not one of the user's keys.
	ErrCredentialNotFound = errors.New("authn: no such security key")
	// ErrBadCredentialName: a key name must be 1-64 printable characters.
	ErrBadCredentialName = errors.New("authn: invalid security key name")
)

// SecurityNotice tells a user, and channels subscribed to security events,
// about a change to their account. Notices are enqueued in the transaction
// of the change.
type SecurityNotice struct {
	Org        ids.OrgID
	User       ids.UUID
	Type       string // security.credential_registered, ..._removed, ..._suspended
	Credential ids.UUID
	Name       string // the key's name, as the user set it
	// Count is set for security.sessions_revoked.
	Count int
	Actor evdomain.Actor
}

// SecurityNotifier enqueues security notices (internal/notifications).
type SecurityNotifier interface {
	SecurityNotice(ctx context.Context, tx db.TenantTx, n SecurityNotice) error
}

// WebAuthnConfig is the relying party: its id is the public host (a domain,
// never an IP address), and the only origin is the public URL's.
type WebAuthnConfig struct {
	RPID, RPName string
	PublicURL    string
}

// WebAuthn implements security-key registration and step-up.
type WebAuthn struct {
	pool   *db.Pool
	wa     *webauthn.WebAuthn
	notify SecurityNotifier
	clock  clock.Clock
	log    *slog.Logger
}

// NewWebAuthn validates cfg and returns the use cases. notify may be nil
// (notices are then only audited).
func NewWebAuthn(pool *db.Pool, cfg WebAuthnConfig, notify SecurityNotifier, clk clock.Clock, log *slog.Logger) (*WebAuthn, error) {
	origin, err := webAuthnOrigin(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.RPName == "" {
		cfg.RPName = "PantherClaw"
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID: cfg.RPID, RPDisplayName: cfg.RPName, RPOrigins: []string{origin},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementDiscouraged, UserVerification: protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: CeremonyTTL, TimeoutUVD: CeremonyTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: CeremonyTTL, TimeoutUVD: CeremonyTTL},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("authn: webauthn: %w", err)
	}
	if log == nil {
		log = pclog.Discard()
	}
	return &WebAuthn{pool: pool, wa: wa, notify: notify, clock: clk, log: log}, nil
}

// webAuthnOrigin checks the relying party (HR-153): the RP id is a domain
// that is the public host or a parent of it, and the public URL is https
// (or http on localhost for development).
func webAuthnOrigin(cfg WebAuthnConfig) (string, error) {
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Host == "" || u.Path != "" && u.Path != "/" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("authn: webauthn public URL must be a bare http(s) origin")
	}
	host := u.Hostname()
	switch {
	case cfg.RPID == "" || net.ParseIP(cfg.RPID) != nil || net.ParseIP(host) != nil:
		return "", errors.New("authn: webauthn needs a domain name as RP id and public host (not an IP address; use localhost for development)")
	case host != cfg.RPID && !strings.HasSuffix(host, "."+cfg.RPID):
		return "", errors.New("authn: webauthn RP id must be the public host or a parent domain of it")
	case u.Scheme != "https" && (u.Scheme != "http" || host != "localhost"):
		return "", errors.New("authn: webauthn needs an https public URL (http only on localhost)")
	}
	return u.Scheme + "://" + u.Host, nil
}

// CounterOK reports whether an assertion's signature counter is acceptable
// after the stored one (HR-154): it must increase, except for synced
// passkeys, which report 0 every time.
func CounterOK(stored, received uint32) bool {
	return received > stored || (stored == 0 && received == 0)
}

// Ceremony is a started ceremony: Options is the JSON the page passes to
// navigator.credentials (create or get); ID comes back with the response.
type Ceremony struct {
	ID      ids.UUID
	Options []byte
}

// CredentialInfo describes one of a user's keys.
type CredentialInfo struct {
	ID                    ids.UUID
	Name                  string
	Algorithm             int32
	Synced                bool // backup eligible: a passkey that can sync between devices
	State, StateReason    string
	CreatedAt             time.Time
	LastUsedAt, ChangedAt *time.Time
	Transports            []string
	AAGUID                string // untrusted (attestation "none")
}

// waUser adapts a user and its active credentials to the library.
type waUser struct {
	id          ids.UUID
	name        string
	credentials []webauthn.Credential
	rowIDs      []ids.UUID
	counts      []uint32
}

func (u *waUser) WebAuthnID() []byte                         { b := u.id; return b[:] }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.name }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// loadUser reads the user's name and active credentials.
func loadUser(ctx context.Context, q *dbq.Queries, org ids.OrgID, user ids.UUID) (*waUser, error) {
	u, err := q.GetUser(ctx, org, user)
	if err != nil {
		return nil, err
	}
	rows, err := q.ActiveCredentialsOfUser(ctx, org, user)
	if err != nil {
		return nil, err
	}
	name := u.Email
	if name == "" {
		name = u.DisplayName
	}
	if name == "" {
		name = u.ID.String()
	}
	wu := &waUser{id: user, name: name}
	for _, r := range rows {
		c := webauthn.Credential{
			ID: r.CredentialID, PublicKey: r.PublicKey, AttestationFormat: r.AttestationFmt,
			Flags:         webauthn.CredentialFlags{UserPresent: true, UserVerified: true, BackupEligible: r.BackupEligible, BackupState: r.BackupState},
			Authenticator: webauthn.Authenticator{SignCount: uint32(r.SignCount)}, //nolint:gosec // G115: the schema bounds sign_count to uint32
		}
		for _, t := range r.Transports {
			c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
		}
		wu.credentials = append(wu.credentials, c)
		wu.rowIDs = append(wu.rowIDs, r.ID)
		wu.counts = append(wu.counts, c.Authenticator.SignCount)
	}
	return wu, nil
}

func descriptors(cs []webauthn.Credential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, len(cs))
	for i := range cs {
		out[i] = cs[i].Descriptor()
	}
	return out
}

func credentialParams() []protocol.CredentialParameter {
	out := make([]protocol.CredentialParameter, len(allowedAlgorithms))
	for i, a := range allowedAlgorithms {
		out[i] = protocol.CredentialParameter{Type: protocol.PublicKeyCredentialType, Algorithm: a}
	}
	return out
}

// recentlyProven applies HR-155: a provider sign-in at most RecentSignIn
// old, or a step-up on this session at most StepUpLifetime old with a key
// that is still active.
func recentlyProven(s BrowserSession, active []ids.UUID) bool {
	if s.SignedInWithin(RecentSignIn) {
		return true
	}
	if !s.SteppedUpWithin(StepUpLifetime) {
		return false
	}
	for _, id := range active {
		if id == s.StepUpCredential {
			return true
		}
	}
	return false
}

// BeginRegistration starts adding a key (HR-155): the session must have
// signed in at the provider at most 5 minutes ago, or stepped up with an
// active key. Existing keys are excluded so one authenticator is never
// registered twice.
func (w *WebAuthn) BeginRegistration(ctx context.Context, s BrowserSession) (Ceremony, error) {
	var out Ceremony
	err := w.pool.InTenantTx(ctx, s.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		u, err := loadUser(ctx, q, s.Org, s.User())
		if err != nil {
			return err
		}
		if !recentlyProven(s, u.rowIDs) {
			return ErrRecentAuthRequired
		}
		if len(u.credentials) >= MaxCredentialsPerUser {
			return ErrTooManyCredentials
		}
		creation, sd, err := w.wa.BeginRegistration(u, webauthn.WithCredentialParameters(credentialParams()),
			webauthn.WithExclusions(descriptors(u.credentials)))
		if err != nil {
			return err
		}
		return w.storeCeremony(ctx, q, s, purposeRegistration, sd, creation, &out)
	})
	return out, err
}

// storeCeremony records a begun ceremony (HR-153) and fills out.
func (w *WebAuthn) storeCeremony(ctx context.Context, q *dbq.Queries, s BrowserSession, purpose string, sd *webauthn.SessionData, options any, out *Ceremony) error {
	raw, err := decodeChallenge(sd.Challenge)
	if err != nil {
		return err
	}
	opts, err := json.Marshal(options)
	if err != nil {
		return err
	}
	allowed := sd.AllowedCredentialIDs
	if allowed == nil {
		allowed = [][]byte{} // registration: none, stored as an empty array
	}
	out.ID = ids.NewV7()
	out.Options = opts
	return q.InsertCeremony(ctx, dbq.InsertCeremonyParams{
		OrgID: s.Org, ID: out.ID, SessionID: s.ID, UserID: s.User(), Purpose: purpose, Challenge: raw,
		AllowedCredentials: allowed, TtlSeconds: int32(CeremonyTTL / time.Second),
	})
}

func decodeChallenge(s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("authn: webauthn challenge is not 32 bytes")
	}
	return raw, nil
}

// sessionData rebuilds the library's ceremony state from a consumed row.
func (w *WebAuthn) sessionData(user ids.UUID, row dbq.ConsumeCeremonyRow, registration bool) webauthn.SessionData {
	sd := webauthn.SessionData{
		Challenge: base64.RawURLEncoding.EncodeToString(row.Challenge), RelyingPartyID: w.wa.Config.RPID,
		UserID: user[:], AllowedCredentialIDs: row.AllowedCredentials, Expires: row.ExpiresAt,
		UserVerification: protocol.VerificationRequired,
	}
	if registration {
		sd.CredParams = credentialParams()
	}
	return sd
}

// consume uses up a ceremony of this session and user (HR-153). It commits
// on its own, so a failed verification still spends the ceremony.
func (w *WebAuthn) consume(ctx context.Context, s BrowserSession, id ids.UUID, purpose string) (dbq.ConsumeCeremonyRow, error) {
	var row dbq.ConsumeCeremonyRow
	err := w.pool.InTenantTx(ctx, s.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		row, err = dbq.New(tx).ConsumeCeremony(ctx, dbq.ConsumeCeremonyParams{
			OrgID: s.Org, ID: id, SessionID: s.ID, UserID: s.User(), Purpose: purpose,
		})
		return notFoundAs(err, ErrCeremonyInvalid)
	})
	return row, err
}

// checkKey enforces the algorithm list and the RSA key size (HR-153).
func checkKey(cose []byte) (int32, error) {
	key, err := webauthncose.ParsePublicKey(cose)
	if err != nil {
		return 0, ErrWebAuthnFailed
	}
	var alg int64
	switch k := key.(type) {
	case webauthncose.EC2PublicKeyData:
		alg = k.Algorithm
	case webauthncose.OKPPublicKeyData:
		alg = k.Algorithm
	case webauthncose.RSAPublicKeyData:
		alg = k.Algorithm
		if new(big.Int).SetBytes(k.Modulus).BitLen() < minRSABits {
			return 0, ErrWebAuthnFailed
		}
	default:
		return 0, ErrWebAuthnFailed
	}
	for _, a := range allowedAlgorithms {
		if int64(a) == alg {
			return int32(alg), nil //nolint:gosec // G115: alg is one of the three listed COSE values
		}
	}
	return 0, ErrWebAuthnFailed
}

// ValidCredentialName reports whether name is an acceptable key name.
func ValidCredentialName(name string) bool {
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 64 || strings.TrimSpace(name) != name {
		return false
	}
	return td.SanitizeClaim(name, 64) == name
}

// FinishRegistration verifies the browser's response to a registration
// ceremony and stores the key: origin, RP id hash, challenge, user
// verification and the algorithm list are checked (HR-153), and the key's
// id must be new in the org. The user is notified (HR-155).
func (w *WebAuthn) FinishRegistration(ctx context.Context, s BrowserSession, ceremony ids.UUID, name string, response []byte) (CredentialInfo, error) {
	if !ValidCredentialName(name) {
		return CredentialInfo{}, ErrBadCredentialName
	}
	if len(response) > maxResponseBytes {
		return CredentialInfo{}, ErrWebAuthnFailed
	}
	parsed, perr := protocol.ParseCredentialCreationResponseBytes(response)
	row, err := w.consume(ctx, s, ceremony, purposeRegistration)
	if err != nil {
		return CredentialInfo{}, err
	}
	if perr != nil {
		return CredentialInfo{}, w.verifyFailed(ctx, s, "registration_parse", perr)
	}
	var out CredentialInfo
	err = w.pool.InTenantTx(ctx, s.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		u, err := loadUser(ctx, q, s.Org, s.User())
		if err != nil {
			return err
		}
		if len(u.credentials) >= MaxCredentialsPerUser {
			return ErrTooManyCredentials
		}
		c, err := w.wa.CreateCredential(u, w.sessionData(s.User(), row, true), parsed)
		if err != nil {
			return w.verifyFailed(ctx, s, "registration_verify", err)
		}
		if !c.Flags.UserVerified {
			return w.verifyFailed(ctx, s, "registration_no_uv", nil)
		}
		alg, err := checkKey(c.PublicKey)
		if err != nil {
			return w.verifyFailed(ctx, s, "registration_algorithm", nil)
		}
		var aaguid *ids.UUID
		if a, err := uuidFromBytes(c.Authenticator.AAGUID); err == nil && !a.IsZero() {
			aaguid = &a
		}
		transports := make([]string, 0, len(c.Transport))
		for _, t := range c.Transport {
			if len(transports) < 8 && len(t) <= 32 {
				transports = append(transports, string(t))
			}
		}
		fmtName := c.AttestationFormat
		if fmtName == "" {
			fmtName = "none"
		}
		out = CredentialInfo{
			ID: ids.NewV7(), Name: name, Algorithm: alg, Synced: c.Flags.BackupEligible, State: "ACTIVE",
			CreatedAt: s.Now, Transports: transports,
		}
		if aaguid != nil {
			out.AAGUID = aaguid.String()
		}
		err = q.InsertCredential(ctx, dbq.InsertCredentialParams{
			OrgID: s.Org, ID: out.ID, UserID: s.User(), CredentialID: c.ID, PublicKey: c.PublicKey, Alg: alg,
			SignCount: int64(c.Authenticator.SignCount), BackupEligible: c.Flags.BackupEligible, BackupState: c.Flags.BackupState,
			Transports: transports, Aaguid: aaguid, AttestationFmt: fmtName, Name: name,
		})
		if db.IsUniqueViolation(err) {
			return ErrCredentialExists
		}
		if err != nil {
			return err
		}
		return w.changed(ctx, tx, s.Org, s.User(), "security.credential_registered", auditkind.AuthnWebauthnRegistered, out.ID, name, s.Actor())
	})
	return out, err
}

func uuidFromBytes(b []byte) (ids.UUID, error) {
	var u ids.UUID
	if len(b) != len(u) {
		return u, errors.New("authn: AAGUID is not 16 bytes")
	}
	copy(u[:], b)
	return u, nil
}

func (w *WebAuthn) verifyFailed(ctx context.Context, s BrowserSession, reason string, err error) error {
	attrs := []slog.Attr{slog.String("reason", reason), slog.String("org", s.Org.String()), slog.String("session", s.ID.String())}
	if err != nil {
		attrs = append(attrs, pclog.Err(err))
	}
	w.log.LogAttrs(ctx, slog.LevelWarn, "authn.webauthn_failed", attrs...)
	return ErrWebAuthnFailed
}

// changed audits a change to a user's key and notifies the user.
func (w *WebAuthn) changed(ctx context.Context, tx db.TenantTx, org ids.OrgID, user ids.UUID, notice, event string, id ids.UUID, name string, actor evdomain.Actor) error {
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: event, Actor: actor, Outcome: audit.Success,
		Object: &audit.Object{Type: "webauthn_credential", ID: id.String()}, Details: map[string]string{"user": user.String()},
	}); err != nil {
		return err
	}
	if w.notify == nil {
		return nil
	}
	return w.notify.SecurityNotice(ctx, tx, SecurityNotice{Org: org, User: user, Type: notice, Credential: id, Name: name, Actor: actor})
}

// BeginStepUp starts a step-up with one of the user's active keys.
func (w *WebAuthn) BeginStepUp(ctx context.Context, s BrowserSession) (Ceremony, error) {
	var out Ceremony
	err := w.pool.InTenantTx(ctx, s.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		u, err := loadUser(ctx, q, s.Org, s.User())
		if err != nil {
			return err
		}
		if len(u.credentials) == 0 {
			return ErrNoCredentials
		}
		assertion, sd, err := w.wa.BeginLogin(u, webauthn.WithAllowedCredentials(descriptors(u.credentials)),
			webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			return err
		}
		return w.storeCeremony(ctx, q, s, purposeStepUp, sd, assertion, &out)
	})
	return out, err
}

// StepUp is the result of a step-up.
type StepUp struct {
	Credential ids.UUID
	// Rotated replaces the session cookie (HR-150); empty when the request
	// carried a secret inside the rotation grace.
	Rotated string
}

// FinishStepUp verifies an assertion and records the step-up on this
// session (HR-156). The signature counter must move forward, or the key is
// suspended and the step-up refused (HR-154, founder decision 4).
func (w *WebAuthn) FinishStepUp(ctx context.Context, s BrowserSession, ceremony ids.UUID, response []byte) (StepUp, error) {
	if len(response) > maxResponseBytes {
		return StepUp{}, ErrWebAuthnFailed
	}
	parsed, perr := protocol.ParseCredentialRequestResponseBytes(response)
	row, err := w.consume(ctx, s, ceremony, purposeStepUp)
	if err != nil {
		return StepUp{}, err
	}
	if perr != nil {
		return StepUp{}, w.verifyFailed(ctx, s, "assertion_parse", perr)
	}
	var out StepUp
	var suspended bool
	err = w.pool.InTenantTx(ctx, s.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		u, err := loadUser(ctx, q, s.Org, s.User())
		if err != nil {
			return err
		}
		c, err := w.wa.ValidateLogin(u, w.sessionData(s.User(), row, false), parsed)
		if err != nil {
			return w.verifyFailed(ctx, s, "assertion_verify", err)
		}
		if !c.Flags.UserVerified {
			return w.verifyFailed(ctx, s, "assertion_no_uv", nil)
		}
		i := slices.IndexFunc(u.credentials, func(x webauthn.Credential) bool { return bytes.Equal(x.ID, c.ID) })
		if i < 0 {
			return w.verifyFailed(ctx, s, "assertion_unknown_credential", nil)
		}
		id, received := u.rowIDs[i], parsed.Response.AuthenticatorData.Counter
		if !CounterOK(u.counts[i], received) {
			return w.suspend(ctx, tx, q, s, id, u.counts[i], received, &suspended)
		}
		n, err := q.RecordAssertion(ctx, dbq.RecordAssertionParams{
			OrgID: s.Org, ID: id, SignCount: int64(received), BackupState: c.Flags.BackupState,
		})
		if err != nil {
			return err
		}
		if n == 0 { // a concurrent assertion moved the counter first: treat it as a regression
			return w.suspend(ctx, tx, q, s, id, u.counts[i], received, &suspended)
		}
		if n, err := q.RecordStepUp(ctx, dbq.RecordStepUpParams{OrgID: s.Org, ID: s.ID, UserID: s.User(), CredentialID: &id}); err != nil || n == 0 {
			return errors.Join(err, ErrCeremonyInvalid)
		}
		out.Credential = id
		if len(s.secretHash) == 32 {
			if out.Rotated, err = rotateSession(ctx, q, s.Org, s.ID, s.secretHash, rolesDigest(s.Bindings)); err != nil {
				return err
			}
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.AuthnStepUp, Actor: s.Actor(), Outcome: audit.Success,
			Object:  &audit.Object{Type: "browser_session", ID: s.ID.String()},
			Details: map[string]string{"webauthn_key": id.String()},
		})
		return err
	})
	if suspended && err == nil {
		return StepUp{}, ErrCredentialSuspended
	}
	return out, err
}

// suspend marks a key whose counter did not move forward as a possible
// clone, audits and notifies, and lets the transaction commit; the caller
// then refuses the step-up.
func (w *WebAuthn) suspend(ctx context.Context, tx db.TenantTx, q *dbq.Queries, s BrowserSession, id ids.UUID, stored, received uint32, done *bool) error {
	by := "system:counter-check"
	if _, err := q.SuspendCredential(ctx, &by, s.Org, id); err != nil {
		return err
	}
	w.log.WarnContext(ctx, "authn.webauthn_clone_suspected", slog.String("org", s.Org.String()), slog.String("webauthn_key", id.String()),
		slog.Uint64("stored", uint64(stored)), slog.Uint64("received", uint64(received)))
	*done = true
	return w.changed(ctx, tx, s.Org, s.User(), "security.credential_suspended", auditkind.AuthnWebauthnSuspended, id, "",
		evdomain.Actor{Type: "system", ID: "counter-check"})
}

// ListCredentials lists the caller's keys, newest first.
func (w *WebAuthn) ListCredentials(ctx context.Context, s BrowserSession) ([]CredentialInfo, error) {
	return w.ListUserCredentials(ctx, s.Org, s.User())
}

// ListUserCredentials lists one user's keys; callers check authorization.
func (w *WebAuthn) ListUserCredentials(ctx context.Context, org ids.OrgID, user ids.UUID) ([]CredentialInfo, error) {
	var out []CredentialInfo
	err := w.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListCredentialsOfUser(ctx, org, user)
		if err != nil {
			return err
		}
		out = make([]CredentialInfo, len(rows))
		for i, r := range rows {
			out[i] = CredentialInfo{
				ID: r.ID, Name: r.Name, Algorithm: r.Alg, Synced: r.BackupEligible, State: r.State, StateReason: deref(r.StateReason),
				CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt, ChangedAt: r.ChangedAt, Transports: r.Transports,
			}
			if r.Aaguid != nil {
				out[i].AAGUID = r.Aaguid.String()
			}
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// RenameCredential renames one of the caller's active keys.
func (w *WebAuthn) RenameCredential(ctx context.Context, s BrowserSession, id ids.UUID, name string) error {
	if !ValidCredentialName(name) {
		return ErrBadCredentialName
	}
	return w.pool.InTenantTx(ctx, s.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.RenameCredential(ctx, dbq.RenameCredentialParams{Name: name, OrgID: s.Org, ID: id, UserID: s.User()})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrCredentialNotFound
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.AuthnWebauthnRenamed, Actor: s.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "webauthn_credential", ID: id.String()},
		})
		return err
	})
}

// RemoveCredential removes one of the caller's keys (HR-155): it needs a
// provider sign-in at most 5 minutes old or a step-up with an active key.
func (w *WebAuthn) RemoveCredential(ctx context.Context, s BrowserSession, id ids.UUID) error {
	return w.pool.InTenantTx(ctx, s.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		u, err := loadUser(ctx, q, s.Org, s.User())
		if err != nil {
			return err
		}
		if !recentlyProven(s, u.rowIDs) {
			return ErrRecentAuthRequired
		}
		return w.remove(ctx, tx, q, s.Org, s.User(), id, "USER_REMOVED", s.Actor())
	})
}

func (w *WebAuthn) remove(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, user, id ids.UUID, reason string, actor evdomain.Actor) error {
	cur, err := q.CredentialOfUser(ctx, org, id, user)
	if err != nil {
		return notFoundAs(err, ErrCredentialNotFound)
	}
	by := actor.Type + ":" + actor.ID
	n, err := q.RemoveCredential(ctx, dbq.RemoveCredentialParams{Reason: &reason, ChangedBy: &by, OrgID: org, ID: id, UserID: user})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrCredentialNotFound // already removed
	}
	return w.changed(ctx, tx, org, user, "security.credential_removed", auditkind.AuthnWebauthnRemoved, id, cur.Name, actor)
}
