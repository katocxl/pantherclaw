// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Errors of gateway calls.
var (
	ErrBrokerKey       = pcerr.New(pcerr.InvalidArgument, "BROKER_KEY_INVALID", "the broker key is not an X-Wing or MLKEM768-P256 public key")
	ErrBrokerKeyReused = pcerr.New(pcerr.FailedPrecondition, "BROKER_KEY_REUSED", "a retired broker key cannot be registered again")
	ErrRenewal         = pcerr.New(pcerr.FailedPrecondition, "GATEWAY_RENEWAL_REFUSED",
		"only the gateway's current certificate can be renewed; enroll again")
)

// Identity is an authenticated gateway: the org, the gateway and the
// certificate its call came with.
type Identity = ca.Identity

// Enrolled is a new gateway identity.
type Enrolled struct {
	Certificate   []byte
	CACertificate []byte
	Gateway       ids.UUID
	Org           ids.OrgID
	GatewayAPIURL string
}

var errReused = errors.New("gateways: enrollment token reused")

// Enroll exchanges a single-use enrollment token and a certificate request
// signed by the gateway's new key for a 24-hour client certificate (HR-180).
// Every failure gives the same ErrEnrollment; a reused token is audited.
func (s *Service) Enroll(ctx context.Context, token string, csr []byte) (Enrolled, error) {
	tok, err := credential.Parse(credential.GatewayEnrollmentToken, token)
	if err != nil {
		return Enrolled{}, ErrEnrollment
	}
	pub, err := ca.ParseRequest(csr)
	if err != nil {
		return Enrolled{}, ErrEnrollment
	}
	org := tok.Org()
	var out Enrolled
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		// A gateway never enrolls into an org that is not ACTIVE (HR-392).
		if state, err := q.OrgState(ctx, org); db.IsNoRows(err) || (err == nil && state != "ACTIVE") {
			return ErrEnrollment
		} else if err != nil {
			return err
		}
		t, err := q.LockGatewayEnrollmentToken(ctx, org, tok.Hash())
		switch {
		case db.IsNoRows(err):
			return ErrEnrollment
		case err != nil:
			return err
		case t.UsedAt != nil:
			return errReused
		case !t.Live:
			return ErrEnrollment
		}
		g, err := q.LockGateway(ctx, org, t.GatewayID)
		if err != nil || g.State != "ACTIVE" {
			return ErrEnrollment
		}
		// A hosted gateway enrolls only with the token its provisioner minted last.
		if stale, err := q.StaleHostedEnrollment(ctx, org, g.ID, t.ID); err != nil {
			return err
		} else if stale {
			return ErrEnrollment
		}
		id := Identity{Org: org, Gateway: g.ID, Cert: ids.NewV7()}
		iss, err := s.issue(ctx, q, pub, id, "ENROLL", nil)
		if err != nil {
			return err
		}
		if n, err := q.UseGatewayEnrollmentToken(ctx, &id.Cert, org, t.ID); err != nil {
			return err
		} else if n != 1 {
			return ErrEnrollment
		}
		// A hosted gateway's record keeps what its provisioner's token enrolled.
		if err := q.BindHostedEnrollment(ctx, dbq.BindHostedEnrollmentParams{
			CertID: &id.Cert, OrgID: org, GatewayID: &g.ID, EnrollmentID: &t.ID,
		}); err != nil {
			return err
		}
		out = Enrolled{Certificate: iss.DER, CACertificate: s.ca.Certificate(), Gateway: g.ID, Org: org, GatewayAPIURL: s.gatewayAPIURL}
		return record(ctx, tx, gatewayActor(id), "gateway.enrolled", g.ID, map[string]string{
			"certificate_id": id.Cert.String(), "key_thumbprint": iss.Thumbprint, "enrollment_id": t.ID.String(),
		})
	})
	if errors.Is(err, errReused) {
		s.auditReuse(ctx, org, tok.Hash())
		return Enrolled{}, ErrEnrollment
	}
	return out, err
}

// auditReuse records a reused enrollment token in its own transaction (the
// enrollment's rolled back): it can mean the token was stolen and used
// first (T-065).
func (s *Service) auditReuse(ctx context.Context, org ids.OrgID, hash []byte) {
	_ = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		t, err := dbq.New(tx).LockGatewayEnrollmentToken(ctx, org, hash)
		if err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "security.gateway_enrollment_reused", Actor: systemActor, Outcome: audit.Denied, ReasonCode: "ENROLLMENT_REUSED",
			Object: &audit.Object{Type: "gateway", ID: t.GatewayID.String()}, Details: map[string]string{"enrollment_id": t.ID.String()},
		})
		return err
	})
}

// issue signs a certificate for pub and records its row.
func (s *Service) issue(ctx context.Context, q *dbq.Queries, pub ed25519.PublicKey, id Identity, via string, previous *ids.UUID) (ca.Issued, error) {
	iss, err := s.ca.IssueClient(pub, id, s.clk.Now())
	if err != nil {
		return ca.Issued{}, err
	}
	err = q.InsertGatewayCert(ctx, dbq.InsertGatewayCertParams{
		OrgID: id.Org, ID: id.Cert, GatewayID: id.Gateway, Serial: iss.Serial, KeyThumbprint: iss.Thumbprint,
		IssuedVia: via, PreviousID: previous, NotBefore: iss.NotBefore, NotAfter: iss.NotAfter,
	})
	return iss, err
}

// Renew issues a certificate for a new key to the gateway behind a verified
// certificate, which must be its current (ACTIVE, unexpired) one; the old
// certificate is accepted for SupersededGrace more (HR-180).
func (s *Service) Renew(ctx context.Context, id Identity, csr []byte) (Enrolled, error) {
	pub, err := ca.ParseRequest(csr)
	if err != nil {
		return Enrolled{}, pcerr.New(pcerr.InvalidArgument, "CSR_INVALID", "invalid certificate request")
	}
	var out Enrolled
	err = s.pool.InTenantTx(ctx, id.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		old, err := q.LockGatewayCert(ctx, id.Org, id.Cert)
		if err != nil || old.GatewayID != id.Gateway || old.State != "ACTIVE" {
			return ErrRenewal
		}
		g, err := q.LockGateway(ctx, id.Org, id.Gateway)
		if err != nil || g.State != "ACTIVE" {
			return ErrGatewayCredentials
		}
		next := Identity{Org: id.Org, Gateway: id.Gateway, Cert: ids.NewV7()}
		iss, err := s.issue(ctx, q, pub, next, "RENEW", &old.ID)
		if err != nil {
			return err
		}
		if n, err := q.SupersedeGatewayCert(ctx, id.Org, old.ID); err != nil {
			return err
		} else if n != 1 {
			return ErrRenewal
		}
		out = Enrolled{Certificate: iss.DER, CACertificate: s.ca.Certificate(), Gateway: id.Gateway, Org: id.Org, GatewayAPIURL: s.gatewayAPIURL}
		return record(ctx, tx, gatewayActor(id), "gateway.renewed", id.Gateway, map[string]string{
			"certificate_id": next.Cert.String(), "previous_id": old.ID.String(), "key_thumbprint": iss.Thumbprint,
		})
	})
	if err == nil {
		s.auth.forget(id.Cert)
	}
	return out, err
}

// RegisterBrokerKey registers the gateway's seal public key (X-Wing, or
// MLKEM768-P256 from a FIPS gateway; a FIPS server refuses X-Wing, D35),
// over its own mTLS identity only (HR-182). The active key registered again changes
// nothing; a new key becomes the active version and the configuration
// version moves, so credentials sealed to the old key must be sealed again.
func (s *Service) RegisterBrokerKey(ctx context.Context, id Identity, public []byte) (dbq.PcBrokerKey, error) {
	if _, err := pccrypto.ParseSealPublicKey(public); errors.Is(err, pccrypto.ErrSealSuiteNotFIPS) {
		return dbq.PcBrokerKey{}, err // an X-Wing key at a FIPS server (D35)
	} else if err != nil {
		return dbq.PcBrokerKey{}, ErrBrokerKey
	}
	fp := Fingerprint(public)
	var out dbq.PcBrokerKey
	err := s.pool.InTenantTx(ctx, id.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		g, err := q.LockGateway(ctx, id.Org, id.Gateway)
		if err != nil || g.State != "ACTIVE" {
			return ErrGatewayCredentials
		}
		cur, err := q.GetActiveBrokerKey(ctx, id.Org, id.Gateway)
		if err == nil && cur.Fingerprint == fp {
			out = cur
			return nil
		} else if err != nil && !db.IsNoRows(err) {
			return err
		}
		if _, err := q.RetireBrokerKeys(ctx, id.Org, id.Gateway); err != nil {
			return err
		}
		k, err := q.InsertBrokerKey(ctx, dbq.InsertBrokerKeyParams{
			OrgID: id.Org, ID: ids.NewV7(), GatewayID: id.Gateway, PublicKey: public, Fingerprint: fp, CertID: id.Cert,
		})
		if db.IsUniqueViolation(err) {
			return ErrBrokerKeyReused
		} else if err != nil {
			return err
		}
		if _, err := q.BumpGatewayConfig(ctx, id.Org, id.Gateway); err != nil {
			return err
		}
		out = k
		return record(ctx, tx, gatewayActor(id), "gateway.broker_key_registered", id.Gateway, map[string]string{
			"fingerprint": fp, "version": strconv.Itoa(int(k.Version)), "certificate_id": id.Cert.String(),
		})
	})
	return out, err
}

// Fingerprint is the "sha256:<hex>" fingerprint of a broker public key.
func Fingerprint(public []byte) string {
	sum := sha256.Sum256(public)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Authenticate checks a verified client certificate's identity against its
// row on every call (HR-181): the gateway must be ACTIVE and the
// certificate unexpired by the database clock and ACTIVE, or SUPERSEDED by
// a renewal less than SupersededGrace ago. Results are cached at most one
// second. The replica that revokes forgets at once, and every other
// replica forgets the org's entries on its LISTEN pc_containment
// notification (ForgetOrg, G0 M19 D201, HR-492). A check read before a
// forget is not cached after it (the generations, D215), so a revocation
// whose notification arrives is applied from then on; a missed
// notification costs at most authTTL.
func (s *Service) Authenticate(ctx context.Context, id Identity) error {
	if ok, hit := s.auth.get(id, s.clk.Now()); hit {
		if ok {
			return nil
		}
		return ErrGatewayCredentials
	}
	gen := s.auth.generation(id.Org)
	ok := false
	err := s.pool.InTenantTx(ctx, id.Org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GatewayCertAuth(ctx, id.Org, id.Cert)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		now := r.DbNow
		live := r.State == "ACTIVE" || (r.State == "SUPERSEDED" && r.SupersededAt != nil && now.Before(r.SupersededAt.Add(SupersededGrace)))
		// A gateway of an org that is not ACTIVE (DELETED, D22) fails closed
		// (HR-392), like person and API-key sign-ins.
		ok = r.GatewayID == id.Gateway && r.GatewayState == "ACTIVE" && r.OrgState == "ACTIVE" && live &&
			!now.Before(r.NotBefore) && now.Before(r.NotAfter)
		return nil
	})
	if err != nil {
		return err // fail closed, not cached
	}
	s.auth.put(id, ok, s.clk.Now(), gen)
	if !ok {
		return ErrGatewayCredentials
	}
	return nil
}

// authCache remembers recent certificate checks for at most authTTL. Every
// forget moves a generation: the cache's own (forget, forgetGateway) or
// the org's (forgetOrg). A check is cached only if neither moved while it
// was read, so a check read before a revocation was forgotten never
// outlives the forget.
type authCache struct {
	mu      sync.Mutex
	entries map[ids.UUID]authEntry
	all     uint64
	orgs    map[ids.OrgID]uint64
}

type authEntry struct {
	org     ids.OrgID
	gateway ids.UUID
	ok      bool
	until   time.Time
}

// authGen is the cache's and an org's generation when a check began.
type authGen struct{ all, org uint64 }

const (
	authTTL        = time.Second
	authCacheLimit = 4096
)

func newAuthCache() authCache {
	return authCache{entries: map[ids.UUID]authEntry{}, orgs: map[ids.OrgID]uint64{}}
}

func (c *authCache) get(id Identity, now time.Time) (ok, hit bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, found := c.entries[id.Cert]
	if !found || !now.Before(e.until) || e.gateway != id.Gateway {
		return false, false
	}
	return e.ok, true
}

// generation is taken before a check is read from the database.
func (c *authCache) generation(org ids.OrgID) authGen {
	c.mu.Lock()
	defer c.mu.Unlock()
	return authGen{all: c.all, org: c.orgs[org]}
}

// put caches a check read at generation gen, unless a forget came since.
func (c *authCache) put(id Identity, ok bool, now time.Time, gen authGen) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen.all != c.all || gen.org != c.orgs[id.Org] {
		return
	}
	if len(c.entries) >= authCacheLimit {
		clear(c.entries)
	}
	c.entries[id.Cert] = authEntry{org: id.Org, gateway: id.Gateway, ok: ok, until: now.Add(authTTL)}
}

func (c *authCache) forget(cert ids.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.all++
	delete(c.entries, cert)
}

func (c *authCache) forgetAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.all++
	clear(c.entries)
}

func (c *authCache) forgetGateway(gateway ids.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.all++
	for k, e := range c.entries {
		if e.gateway == gateway {
			delete(c.entries, k)
		}
	}
}

func (c *authCache) forgetOrg(org ids.OrgID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.orgs) >= authCacheLimit {
		// Bounded: dropping the org generations moves the cache's own, so
		// no check read before this one is cached either.
		clear(c.orgs)
		c.all++
	}
	c.orgs[org]++
	for k, e := range c.entries {
		if e.org == org {
			delete(c.entries, k)
		}
	}
}

// ForgetOrg drops the cached certificate checks of org's gateways, and
// any check of the org still being read is not cached (D215). The
// containment hub calls it on every pc_containment notification of the
// org, which a revocation (an epoch bump) and a gateway's disable or
// revoke (its state) send, so another replica's revocation applies here
// from the moment its notification arrives; a missed notification costs
// at most authTTL (HR-492). The payload names the org only (HR-056), so
// all of its entries go.
func (s *Service) ForgetOrg(org ids.OrgID) { s.auth.forgetOrg(org) }

// ForgetAll drops every cached certificate check, and any check still
// being read is not cached (D224). The hub calls it on each new LISTEN.
func (s *Service) ForgetAll() { s.auth.forgetAll() }
