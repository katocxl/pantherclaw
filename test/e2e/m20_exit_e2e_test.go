// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	casesdomain "github.com/katocxl/pantherclaw/internal/cases/domain"
	casesstore "github.com/katocxl/pantherclaw/internal/cases/store"
	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/exports"
	"github.com/katocxl/pantherclaw/internal/keystore"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/sigv4"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/sim"
	"github.com/katocxl/pantherclaw/internal/sim/aws"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/ticketsync/adapters/ticketsyncrpc"
	tsapp "github.com/katocxl/pantherclaw/internal/ticketsync/app"
	tsdomain "github.com/katocxl/pantherclaw/internal/ticketsync/domain"
)

// m20Business stands in for the licence of the services the test runs itself.
type m20Business struct{}

func (m20Business) Current(context.Context) (billing.Entitlements, error) {
	e := billing.CommunityEntitlements()
	e.Edition = billing.Business
	return e, nil
}

// TestE2E_M20_IntegrationsBreadth is M20's exit journey (G0 M20 exit criteria,
// D292), one path per feature on one Enterprise stack.
//
//   - Webhooks: the channel, the opt-in and the delivery run in the test; the
//     JWKS the signature verifies against is the running server's public route.
//   - Exports: in-process, on a database of its own, because the stack's
//     workers would otherwise take the push's job, and they do not trust the
//     simulator's certificate.
//   - Rotation: the requests run in the test; every test and confirmation is
//     leased by the running server and probed at the GitHub simulator by the
//     running gateway.
//   - GitLab and ECS: an agent through the running gateway under its grant.
//   - Jira: the setup runs in the test; the webhook goes to the running server,
//     and a refused ticket is leased by it and read by the running gateway.
//
// Covers: PN-018, F517, F424, F756, F545
func TestE2E_M20_IntegrationsBreadth(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", billing: true, people: &p, github: true, gitlab: true, jira: true, awsECS: true})
	if err := hostedPlans(t, s.pool).ApplyPlan(context.Background(), s.org, entitlements.Snapshot{
		PlanID: "enterprise", Edition: "enterprise", Status: entitlements.StatusActive, EventID: "evt_m20_exit", EventAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{s.kek})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("an opted-in destination gets v1a, verifiable against its org's JWKS, with v1", func(t *testing.T) { s.m20Webhook(t, kp) })
	t.Run("a pushed pack leaves a receipt and a later removal a signed notice", m20Export)
	t.Run("a rotation reaches CONFIRMED and a failing candidate leaves the old key", s.m20Rotation)
	t.Run("a GitLab merge and an ECS deploy run under a grant", func(t *testing.T) { s.m20Deploys(t, p) })
	t.Run("Jira Done on a synced case leaves its containment in force", func(t *testing.T) { s.m20JiraDone(t, kp) })
}

// m20Admin is a person in the stack's org holding roles.
func (s *stack) m20Admin(t *testing.T, name string, roles ...td.RoleName) context.Context {
	t.Helper()
	id := ids.NewV7()
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", s.org, id, name)
	bs := make([]td.Binding, 0, len(roles))
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}})
	}
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: id}, Bindings: bs,
	}, Credential: tapp.CredBrowserSession})
}

// m20Hook is one request a webhook receiver got.
type m20Hook struct {
	header http.Header
	body   []byte
}

func (s *stack) m20Webhook(t *testing.T, kp keys.KeyProvider) {
	var mu sync.Mutex
	var got []m20Hook
	r := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		mu.Lock()
		defer mu.Unlock()
		got = append(got, m20Hook{header: req.Header.Clone(), body: b})
	}))
	t.Cleanup(r.Close)
	jc, err := jobs.NewClient(s.pool, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	svc, err := napp.New(s.pool, jc, pccrypto.NewEnvelope(keystore.NewDEKStore(s.pool, kp)),
		napp.Config{PublicURL: s.apiURL, AllowedPrivateRanges: loopback}, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(r.Certificate())
	svc.SetHTTPClient(httpx.NewEgressClient(httpx.EgressConfig{AllowedPrefixes: loopback, RootCAs: roots, Timeout: 5 * time.Second}))
	svc.SetWebhookKeys(keystore.NewWebhookKeys(s.pool, kp))

	var hook napp.CreatedChannel
	if err := s.pool.InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		hook, err = svc.CreateChannelTx(ctx, tx, napp.NewChannel{
			Org: s.org, Name: "m20-exit", Kind: ndomain.KindWebhook, EventTypes: []string{"m20.exit"}, URL: r.URL + "/pc", CreatedBy: "test",
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	admin := s.m20Admin(t, "webhook-admin", td.RoleOrgAdmin)
	ch, jwksURL, err := svc.SetChannelSignatureScheme(admin, hook.ID, string(ndomain.SchemeHMACEd25519))
	if err != nil || ch.SignatureScheme != ndomain.SchemeHMACEd25519 {
		t.Fatalf("opt in: %+v %v", ch, err)
	}
	if jwksURL != s.apiURL+ndomain.WebhookJWKSPath(s.org) {
		t.Fatalf("JWKS URL %s", jwksURL)
	}
	// The row is written here and not through Enqueue: Enqueue's job would go
	// to the stack's worker, which cannot reach this receiver.
	note, delivery := ids.NewV7(), ids.NewV7()
	s.exec(t, `INSERT INTO pc.notifications (org_id, id, type, severity, title, body, link_path, expires_at)
		VALUES ($1, $2, 'security.credential_registered', 'INFO', 'A key was registered', 'alice registered a key', '', now() + interval '1 hour')`, s.org, note)
	s.exec(t, `INSERT INTO pc.deliveries (org_id, id, notification_id, channel_id, kind, state)
		VALUES ($1, $2, $3, $4, 'webhook', 'PENDING')`, s.org, delivery, note, hook.ID)
	if err := svc.Deliver(context.Background(), s.org, delivery); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("%d deliveries", len(got))
	}
	h := got[0]
	id, ts := h.header.Get("webhook-id"), h.header.Get("webhook-timestamp")
	at, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hook.Secret, ndomain.SecretPrefix))
	if err != nil {
		t.Fatal(err)
	}
	sigs := strings.Fields(h.header.Get("webhook-signature"))
	if len(sigs) != 2 || sigs[0] != ndomain.Sign(secret, id, at, h.body) {
		t.Fatalf("signatures %q", sigs)
	}
	keyset := s.m20JWKS(t, jwksURL)
	if len(keyset) != 1 || !ndomain.VerifyV1a(keyset[0], sigs[1], id, at, h.body) {
		t.Fatalf("v1a does not verify against the %d keys of the org's JWKS", len(keyset))
	}
}

// m20JWKS fetches an org's JWKS from the running server.
func (s *stack) m20JWKS(t *testing.T, url string) []ed25519.PublicKey {
	t.Helper()
	res, err := http.Get(url) //nolint:gosec,noctx // G107: the test server's own address
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("JWKS: %d", res.StatusCode)
	}
	var doc struct {
		Keys []jws.JWK `json:"keys"`
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	out := make([]ed25519.PublicKey, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, x)
	}
	return out
}

// m20S3 is a small S3-compatible simulator: whole-object PUT and the
// multipart calls, signed, with the body matching its signed hash.
type m20S3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	parts   map[string]map[int][]byte
	deletes int
}

func (m *m20S3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	body, err := io.ReadAll(r.Body)
	sum := sha256.Sum256(body)
	if err != nil || r.Header.Get("Authorization") == "" || r.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(sum[:]) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	key, q := strings.TrimPrefix(r.URL.Path, "/"), r.URL.Query()
	upload := q.Get("uploadId")
	_, initiate := q["uploads"]
	w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(sum[:]))
	switch {
	case r.Method == http.MethodPost && initiate:
		upload = "upload-" + strconv.Itoa(len(m.parts)+1)
		m.parts[upload] = map[int][]byte{}
		fmt.Fprintf(w, "<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>", upload)
	case r.Method == http.MethodPut && upload != "":
		n, _ := strconv.Atoi(q.Get("partNumber"))
		m.parts[upload][n] = body
		w.Header().Set("ETag", `"part-`+strconv.Itoa(n)+`"`)
	case r.Method == http.MethodPut:
		m.objects[key] = body
		w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:16])+`"`)
	case r.Method == http.MethodPost:
		var in struct {
			Parts []struct {
				PartNumber int `xml:"PartNumber"`
			} `xml:"Part"`
		}
		if err := xml.Unmarshal(body, &in); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var whole bytes.Buffer
		for _, p := range in.Parts {
			whole.Write(m.parts[upload][p.PartNumber])
		}
		m.objects[key] = whole.Bytes()
		fmt.Fprint(w, `<CompleteMultipartUploadResult><ETag>"whole-etag"</ETag></CompleteMultipartUploadResult>`)
	default:
		m.deletes++
		w.WriteHeader(http.StatusNoContent)
	}
}

func (m *m20S3) object(key string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objects[key]
	return b, ok
}

func m20Export(t *testing.T) {
	ctx := context.Background()
	s3 := &m20S3{objects: map[string][]byte{}, parts: map[string]map[int][]byte{}}
	srv := httptest.NewTLSServer(s3)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	d := dbtest.New(t)
	pool := d.AppPool(t)
	org, user, key := ids.New[ids.Org](), ids.NewV7(), ids.NewV7()
	kek := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{kek})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := exports.New(pool, pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp)),
		exports.Config{PublicURL: "https://pc.example.com", RootCAs: roots}, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	reg := keys.NewRegistry()
	signing, err := keys.GenerateSigningKey(keys.PurposeEvidencePacks)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Put(signing); err != nil {
		t.Fatal(err)
	}
	jc, err := jobs.NewClient(pool, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	svc.WithEditions(m20Business{}).WithPushes(jc, nil, reg, nil)
	d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'exports')", org)
	d.AdminExec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", org, user)
	d.AdminExec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		org, key, user, bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32))
	d.AdminExec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
		VALUES ($1, $2, 'org_admin', $3, 'ORG', 'system:test'), ($1, $4, 'security_admin', $3, 'ORG', 'system:test')`, org, ids.NewV7(), user, ids.NewV7())
	scope := td.Scope{Type: td.ScopeOrg, ID: org.UUID()}
	admin := tapp.WithCaller(ctx, tapp.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
		Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: scope}, {Role: td.RoleSecurityAdmin, Scope: scope}},
	}})

	dest, err := svc.Create(admin, exports.NewDestination{
		Name: "vault", DataClasses: []string{exports.ClassEvidencePacks},
		Credential: exports.Credential{S3: sigv4.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret/value+1"}},
		Target:     exports.Target{Kind: exports.KindS3, URL: srv.URL, Bucket: "bkt", Region: "eu-west-1", PathStyle: true, Internal: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Activate(admin, dest.ID, stepup.StepUp{Credential: key, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("evidence "), 10)
	sum := sha256.Sum256(content)
	pack := ids.NewV7()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d.AdminExec(t, `INSERT INTO pc.evidence_packs (org_id, id, created_by, scope_kind, scope, include, state, manifest, manifest_sha256,
		content, content_sha256, content_size, items, ready_at, expires_at)
		VALUES ($1, $2, $3, 'run', '{}', '{"receipts": true}'::jsonb, 'READY', 'signed-manifest-text', $4, $5, $4, $6, 0, $7, $7::timestamptz + interval '7 days')`,
		org, pack, user, sum[:], content, int64(len(content)), now)

	r, err := svc.Push(admin, exports.PushRequest{Destination: dest.ID, Class: exports.ClassEvidencePacks, Artifact: pack})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Run(ctx, org, r.ID, true); err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetReceipt(admin, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != exports.ReceiptDelivered || got.SHA256 != hex.EncodeToString(sum[:]) || got.DeliveredAt == nil {
		t.Fatalf("receipt %+v", got)
	}
	if b, ok := s3.object("bkt/" + got.ObjectKey); !ok || !bytes.Equal(b, content) {
		t.Fatalf("object %q %v", b, ok)
	}

	d.AdminExec(t, "UPDATE pc.evidence_packs SET state = 'EXPIRED', content = NULL WHERE org_id = $1 AND id = $2", org, pack)
	if err := svc.Sweep(ctx, org); err != nil {
		t.Fatal(err)
	}
	if got, err = svc.GetReceipt(admin, r.ID); err != nil {
		t.Fatal(err)
	}
	if got.NoticeState != "SENT" || got.RemovedHereAt == nil {
		t.Fatalf("after the removal: %+v", got)
	}
	notice, ok := s3.object("bkt/" + got.NoticeKey)
	if !ok {
		t.Fatalf("no notice at %s", got.NoticeKey)
	}
	v, err := reg.Verifier(keys.PurposeEvidencePacks, exports.NoticeJWSType)
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := v.Verify(string(notice))
	if err != nil {
		t.Fatal(err)
	}
	var n exports.RemovalNotice
	if err := json.Unmarshal(payload, &n); err != nil {
		t.Fatal(err)
	}
	if n.ObjectKey != got.ObjectKey || n.SHA256 != got.SHA256 || n.Artifact != pack.String() {
		t.Fatalf("notice %+v", n)
	}
	if b, ok := s3.object("bkt/" + got.ObjectKey); !ok || !bytes.Equal(b, content) || s3.deletes != 0 {
		t.Fatalf("the pushed copy changed: %v, %d deletes", ok, s3.deletes)
	}
}

// m20Candidate seals key as a rotation's candidate, as pclaw seal does.
func (s *stack) m20Candidate(t *testing.T, svc *credapp.Service, admin context.Context, rotation ids.UUID, key *rsa.PrivateKey) {
	t.Helper()
	k, err := svc.GetSealingKey(admin, s.gh.conn)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pccrypto.ParseSealPublicKey(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	plain, err := creddomain.GitHubApp{V: 1, Issuer: s.gh.app, Installation: s.gh.installation, Account: s.gh.account, PrivateKey: pemKey}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	b := k.Binding
	b.Kind = creddomain.KindGitHubApp
	sealed, err := pccrypto.Seal(pub, b.Info(), creddomain.AAD, plain)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SealCandidate(admin, rotation, credapp.PutInput{
		Connection: s.gh.conn, BrokerKey: mustUUID(t, b.BrokerKey), Version: b.Version, Sealed: sealed, AllowedHosts: b.AllowedHosts,
		Header: b.Header, Scheme: b.Scheme, Kind: creddomain.KindGitHubApp,
		GitHub: &creddomain.Installation{AppClientID: s.gh.app, ID: s.gh.installation, Account: s.gh.account},
	}); err != nil {
		t.Fatal(err)
	}
}

func (s *stack) m20Rotation(t *testing.T) {
	admin := s.person(t, "rotator", td.RoleGatewayAdmin)
	digest := sha256.Sum256([]byte("preview"))
	svc := credapp.New(s.pool, nil).WithRotations(func(context.Context, db.TenantTx, ids.UUID, int32) ([]byte, error) { return digest[:], nil })
	const rotationState = "SELECT state FROM pc.credential_rotations WHERE id = $1"
	credential := func(id ids.UUID) string {
		t.Helper()
		var state string
		s.query(t, "SELECT state FROM pc.credentials WHERE id = $1", []any{id}, &state)
		return state
	}
	generate := func() *rsa.PrivateKey {
		t.Helper()
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}

	// A candidate the App does not know fails its test; the old key stays.
	failing, err := svc.RequestRotation(admin.ctx, s.gh.conn, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	s.eventually(t, string(creddomain.RotationRequested), rotationState, failing.ID)
	s.m20Candidate(t, svc, admin.ctx, failing.ID, generate())
	if _, err := svc.TestRotation(admin.ctx, failing.ID); err != nil {
		t.Fatal(err)
	}
	s.eventually(t, string(creddomain.RotationFailed), rotationState, failing.ID)
	if state := credential(failing.OldCredentialID); state != "ACTIVE" {
		t.Fatalf("the old key after a failed candidate: %s", state)
	}

	// A key the App accepts goes from REQUESTED to CONFIRMED, and the old
	// key is revoked only once GitHub refuses it.
	key := generate()
	s.gh.sim.AddAppKey(&key.PublicKey)
	r, err := svc.RequestRotation(admin.ctx, s.gh.conn, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	s.eventually(t, string(creddomain.RotationRequested), rotationState, r.ID)
	s.m20Candidate(t, svc, admin.ctx, r.ID, key)
	if _, err := svc.TestRotation(admin.ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	s.eventually(t, "true", "SELECT (test_passed_at IS NOT NULL)::text FROM pc.credential_rotations WHERE id = $1", r.ID)
	if _, err := svc.ActivateRotation(admin.ctx, r.ID, stepup.StepUp{Credential: admin.key, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	s.eventually(t, string(creddomain.RotationActivating), rotationState, r.ID)
	var gateway ids.UUID
	s.query(t, "SELECT gateway_id FROM pc.connections WHERE id = $1", []any{s.gh.conn}, &gateway)
	s.waitConfig(t, s.configVersion(t, gateway))
	s.gh.sim.RevokeAppKey(&s.gh.key.PublicKey)
	if _, err := svc.ConfirmRotation(admin.ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	s.eventually(t, string(creddomain.RotationConfirmed), rotationState, r.ID)
	got, err := svc.GetRotation(admin.ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if old, candidate := credential(got.OldCredentialID), credential(*got.CandidateCredentialID); old != "REVOKED" || candidate != "ACTIVE" {
		t.Fatalf("after the rotation: old %s, new %s", old, candidate)
	}
}

func (s *stack) m20Deploys(t *testing.T, p idp) {
	d := newRangeDriver(t)
	d.s, d.people = s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	d.sc = domain.Scenario{ID: "M20-EXIT", Requires: []string{string(capGitLabMerge), string(capAWSECS)}}
	d.setupM20Connectors()
	hurry := func(txn string) {
		s.db.AdminExec(t, "UPDATE pc.verifications SET next_at = now() WHERE transaction_id = $1 AND state = 'PENDING'", mustUUID(t, txn))
	}

	merge := d.gitlabMerge(t, sim.GitLabMergeRequest, sim.GitLabHead)
	if merge.Outcome != domain.OutcomeAllow {
		t.Fatalf("merge: %+v", merge)
	}
	if m, _ := s.gitlab.sim.MergeRequest(sim.GitLabProject, sim.GitLabMergeRequest); m.Merges != 1 {
		t.Fatalf("merge request: %+v", m)
	}
	s.eventually(t, "CONFIRMED", ecsEffect, merge.TransactionID)
	deployments := s.gitlab.sim.Deployments(sim.GitLabProject)
	if len(deployments) != 1 {
		t.Fatalf("deployments: %+v", deployments)
	}
	s.gitlab.sim.SetDeployment(deployments[0].ID, "success")
	consequence := s.consequenceOf(t, merge.TransactionID)
	if consequence == "" {
		t.Fatal("no consequence transaction for the deployment")
	}
	hurry(consequence)
	s.eventually(t, "CONFIRMED", ecsDownstream, merge.TransactionID)

	d.setupAWSECS() // the agent's grant for the deploy, on a run of its own
	deploy := d.ecsDeploy(t, aws.Service, aws.Account, 2)
	if deploy.Outcome != domain.OutcomeAllow || s.aws.sim.ServiceTaskDefinition() != aws.TaskDefinition(2) {
		t.Fatalf("deploy: %+v, the service runs %s", deploy, s.aws.sim.ServiceTaskDefinition())
	}
	s.eventually(t, "CONFIRMED", ecsEffect, deploy.TransactionID)
	s.aws.sim.SetRollout(aws.RolloutCompleted)
	rollout := s.consequenceOf(t, deploy.TransactionID)
	if rollout == "" {
		t.Fatal("no consequence transaction for the rollout")
	}
	hurry(rollout)
	s.eventually(t, "CONFIRMED", ecsDownstream, deploy.TransactionID)
	if calls := s.aws.sim.Calls(); !slices.ContainsFunc(calls, func(c aws.Call) bool { return c.Action == "UpdateService" && c.Key == "session" }) {
		t.Fatalf("calls: %+v", calls)
	}
}

func (s *stack) m20JiraDone(t *testing.T, kp keys.KeyProvider) {
	ctx := context.Background()
	admin := s.m20Admin(t, "ticket-admin", td.RoleGatewayAdmin, td.RoleSecurityAdmin, td.RoleResponder)
	person, err := tapp.CallerFrom(admin)
	if err != nil {
		t.Fatal(err)
	}
	svc := &tsapp.Service{Pool: s.pool, Envelope: pccrypto.NewEnvelope(keystore.NewDEKStore(s.pool, kp)), Editions: m20Business{}}
	cfg, secret, err := svc.CreateConfig(admin, s.jira.conn, "SEC")
	if err != nil {
		t.Fatal(err)
	}
	open := func(title string) casesdomain.Case {
		t.Helper()
		var c casesdomain.Case
		if err := s.pool.InTenantTx(ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			c, err = casesstore.Open(ctx, tx, casesdomain.NewCase{
				Title: title, Source: "manual", OpenedBy: casesdomain.Author{Type: "user", ID: person.Principal.ID.String()},
			})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return c
	}
	kase := open("leaked token")
	if _, err := svc.LinkCase(admin, kase.ID, cfg.ID, "SEC-7"); err != nil {
		t.Fatal(err)
	}
	action, control, agent := ids.NewV7(), ids.NewV7(), ids.NewV7().String()
	actor := "user:" + person.Principal.ID.String()
	s.exec(t, `INSERT INTO pc.response_actions (org_id, id, kind, scope_type, scope_id, control, reason, case_id, actor, source, status)
		VALUES ($1, $2, 'CONTAIN', 'agent', $3, 'DENY_ALL', 'contain', $4, $5, 'PERSON', 'REQUESTED')`, s.org, action, agent, kase.ID, actor)
	s.exec(t, `INSERT INTO pc.containment_controls (org_id, id, action_id, scope_type, scope_id, control, reason, case_id, created_by)
		VALUES ($1, $2, $3, 'agent', $4, 'DENY_ALL', 'contain', $5, $6)`, s.org, control, action, agent, kase.ID, actor)
	epoch := func() int {
		t.Helper()
		var n int
		s.query(t, "SELECT coalesce((SELECT epoch FROM pc.org_containment WHERE org_id = $1), 0)::int", []any{s.org}, &n)
		return n
	}
	before := epoch()

	body := fmt.Appendf(nil, `{"timestamp":%d,"webhookEvent":"jira:issue_updated",
		"issue":{"key":"SEC-7","fields":{"status":{"statusCategory":{"key":"done"}}}},
		"changelog":{"items":[{"field":"status","fromString":"To Do","toString":"Done"}]}}`, time.Now().UnixMilli())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.apiURL+ticketsyncrpc.WebhookPath+s.org.String()+"/"+cfg.ID.String(), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(tsdomain.JiraDeliveryHeader, "m20-exit-1")
	req.Header.Set(tsdomain.JiraSignatureHeader, tsdomain.SignJira(secret, body))
	res, err := http.DefaultClient.Do(req) //nolint:gosec // G704: the test server's own address
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("webhook: %d", res.StatusCode)
	}

	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		s.query(t, sql, args, &n)
		return n
	}
	if n := count(`SELECT count(*) FROM pc.case_entries WHERE case_id = $1 AND kind = 'EXTERNAL' AND text LIKE '%never restores authority%'`, kase.ID); n != 1 {
		t.Fatalf("the Done was not noted: %d", n)
	}
	if n := count("SELECT count(*) FROM pc.containment_controls WHERE id = $1 AND lifted_at IS NULL", control); n != 1 {
		t.Fatal("the containment control was lifted")
	}
	if e := epoch(); e != before {
		t.Fatalf("the containment epoch moved from %d to %d", before, e)
	}
	if n := count("SELECT count(*) FROM pc.restoration_plans"); n != 0 {
		t.Fatalf("%d restoration plans", n)
	}
	if n := count("SELECT count(*) FROM pc.cases WHERE id = $1 AND state = 'OPEN'", kase.ID); n != 1 {
		t.Fatal("the case moved")
	}

	// A ticket for a customer-visible project goes through the running
	// server and gateway, and ends refused with nothing sent (D277, HR-522).
	help, _, err := svc.CreateConfig(admin, s.jira.conn, sim.JiraHelpDesk)
	if err != nil {
		t.Fatal(err)
	}
	refused := open("customer must not read this")
	issues := len(s.jira.sim.Issues())
	out, err := svc.OpenCaseTicket(admin, refused.ID, help.ID)
	if err != nil {
		t.Fatal(err)
	}
	s.eventually(t, "FAILED external_project", "SELECT state || ' ' || coalesce(result_code, '') FROM pc.ticket_outbound WHERE id = $1", out)
	if state := s.row(t, `SELECT v.state FROM pc.verifications v JOIN pc.ticket_outbound o ON o.org_id = v.org_id AND o.verification_id = v.id
		WHERE o.id = $1`, out); state != "DONE" {
		t.Fatalf("the task: %s", state)
	}
	audited := s.row(t, "SELECT convert_from(body, 'UTF8') FROM pc.ledger_entries WHERE kind = 'audit.ticket.sync_failed'")
	if !strings.Contains(audited, out.String()) || !strings.Contains(audited, tsapp.RefusedExternal) {
		t.Fatalf("the refusal was not audited: %s", audited)
	}
	if n := len(s.jira.sim.Issues()); n != issues {
		t.Fatalf("%d issues, %d before the refused write", n, issues)
	}
}
