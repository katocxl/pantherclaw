// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package exports

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/riverqueue/river"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/platform/sigv4"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Parameters of a push.
const (
	// UploadPartBytes is the size of an upload part: an artifact above it
	// goes as a multipart upload or chunked PUTs. S3 wants 5 MiB or more of
	// every part but the last, which is why parts are cut from the stream
	// and not taken from the artifact.
	UploadPartBytes = 64 << 20
	// StreamWait is how long a streamed push waits for its export to start.
	StreamWait = time.Hour
	// StreamTimeout bounds a streamed export's build.
	StreamTimeout = 6 * time.Hour
	// staleAfter is past any push's end: a receipt still PUSHING then was
	// left by a crash.
	staleAfter = StreamTimeout + 2*time.Hour
	// keepAliveEvery keeps a build's transaction from the idle timeout
	// while it waits for the uploader.
	keepAliveEvery = 3 * time.Second
	abortTimeout   = 30 * time.Second
	abortAttempts  = 3
	// pushTimeout bounds one attempt of a stored artifact's push.
	pushTimeout  = time.Hour
	pushAttempts = 3
	// maxSweepItems bounds what one org's sweep does on the network; the next
	// hour continues.
	maxSweepItems = 20
	// FailureKind is the owned failure kind of failing delivery.
	FailureKind = "export.delivery_failing"
)

// Receipt states.
const (
	ReceiptQueued    = "QUEUED"
	ReceiptPushing   = "PUSHING"
	ReceiptDelivered = "DELIVERED"
	ReceiptFailed    = "FAILED"
)

// Actor records pushes that no person is running.
var Actor = evdomain.Actor{Type: "system", ID: "evidence-exports"}

// Errors of a push request.
var (
	ErrPush = pcerr.New(pcerr.InvalidArgument, "INVALID_EXPORT_PUSH",
		"a push names a destination and a class: a pack id, a ready export id, a streamed export, or a ledger range of at most 1000 entries")
	ErrClass    = pcerr.New(pcerr.FailedPrecondition, "EXPORT_CLASS_REFUSED", "this destination does not receive this data class")
	ErrArtifact = pcerr.New(pcerr.FailedPrecondition, "EXPORT_ARTIFACT_UNAVAILABLE", "the artifact is not ready, or it has expired")
	ErrReceipt  = pcerr.New(pcerr.NotFound, "EXPORT_RECEIPT_NOT_FOUND", "receipt not found")
)

// BundleExporter builds proof bundles (evapp.Service).
type BundleExporter interface {
	ExportBundle(ctx context.Context, sel evapp.Selection, consistencyFrom uint64) (evapp.Export, error)
}

// WithPushes sets what pushes need: the jobs client, the proof bundles, the
// registry that signs removal notices and the sink of owned failures.
func (s *Service) WithPushes(j *jobs.Client, b BundleExporter, k *keys.Registry, f reflexports.FailureSink) *Service {
	s.jobs, s.bundles, s.keys, s.failures = j, b, k, f
	return s
}

// PushRequest asks for one artifact to be pushed.
type PushRequest struct {
	Destination ids.UUID
	Class       string
	// Artifact is the pack or the ready export.
	Artifact ids.UUID
	// Stream waits for the requester's next export and streams it straight
	// to the destination, whatever its size. The person starts the export on
	// its confirmation page as always.
	Stream bool
	// FromSeq and ToSeq are a proof bundle's ledger range.
	FromSeq, ToSeq int64
}

// Receipt is the record of one push (HR-514).
type Receipt struct {
	ID              ids.UUID
	Destination     ids.UUID
	DestinationName string
	Class           string
	Artifact        *ids.UUID
	Streamed        bool
	FromSeq, ToSeq  int64
	RequestedBy     ids.UUID
	ObjectKey       string
	State           string
	AbortState      string
	SizeBytes       int64
	SHA256          string
	Parts           int
	ETag            string
	Attempts        int
	LastStatus      int
	FailureCode     string
	CreatedAt       time.Time
	StartedAt       *time.Time
	DeliveredAt     *time.Time
	RemovedHereAt   *time.Time
	NoticeState     string
	NoticeKey       string
	NoticeSHA256    string
	NoticeSentAt    *time.Time
	// Status is what may be said of the artifact (HR-515): once the copy
	// here is gone, only that a copy exists at the destination, never that
	// the copy there is gone.
	Status string
}

func statusOf(state, destination string, removed *time.Time) string {
	switch {
	case removed != nil:
		return "removed here; a copy exists at " + destination
	case state == ReceiptDelivered:
		return "delivered to " + destination
	case state == ReceiptFailed:
		return "not delivered to " + destination
	}
	return "on its way to " + destination
}

func classPermissions(class string) []td.Permission {
	switch class {
	case ClassEvidencePacks:
		return []td.Permission{td.PermEvidenceExport, td.PermEvidenceRead}
	case ClassProofBundles:
		return []td.Permission{td.PermEvidenceRead}
	case ClassOrgExports:
		return []td.Permission{td.PermDataExport}
	}
	return nil
}

func objectKey(prefix, class string, org ids.OrgID, receipt ids.UUID, name string) string {
	key := class + "/" + org.String() + "/" + receipt.String() + "/" + name
	if prefix != "" {
		return prefix + "/" + key
	}
	return key
}

func (r PushRequest) valid() (string, bool) {
	switch r.Class {
	case ClassEvidencePacks:
		return "pack-" + r.Artifact.String() + ".zip", !r.Artifact.IsZero() && !r.Stream && r.FromSeq == 0 && r.ToSeq == 0
	case ClassProofBundles:
		return fmt.Sprintf("bundle-%d-%d.json", r.FromSeq, r.ToSeq), r.Artifact.IsZero() && !r.Stream && r.FromSeq > 0 && r.ToSeq >= r.FromSeq &&
			r.ToSeq-r.FromSeq < evapp.MaxRange
	case ClassOrgExports:
		return "export.zip-parts", r.Artifact.IsZero() == r.Stream && r.FromSeq == 0 && r.ToSeq == 0
	}
	return "", false
}

// Push records a QUEUED receipt and queues the push (siem.manage, a
// person, Business). The artifact's own permission is needed too, and the
// destination must take the class: a refusal is audited and sends nothing
// (T-223). An active legal hold never blocks a push: it keeps data here, it
// does not stop a copy leaving.
func (s *Service) Push(ctx context.Context, in PushRequest) (Receipt, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return Receipt{}, err
	}
	name, ok := in.valid()
	if !ok {
		return Receipt{}, ErrPush
	}
	for _, p := range classPermissions(in.Class) {
		if err := c.Require(p, td.OrgPath(c.Org)); err != nil {
			return Receipt{}, err
		}
	}
	id := ids.NewV7()
	var out Receipt
	var refused error
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		d, err := get(ctx, q, c.Org, in.Destination)
		if err != nil {
			return err
		}
		if d.State != StateActive {
			return ErrState
		}
		captures := false
		switch in.Class {
		case ClassEvidencePacks:
			p, err := q.GetPackForPush(ctx, c.Org, in.Artifact)
			if db.IsNoRows(err) || (err == nil && (p.State != "READY" || !p.Live)) {
				return ErrArtifact
			} else if err != nil {
				return err
			}
			captures = p.Captures
		case ClassOrgExports:
			if !in.Stream {
				r, err := q.GetExportForPush(ctx, c.Org, in.Artifact)
				if db.IsNoRows(err) || (err == nil && (r.State != "READY" || r.Parts == 0 || !r.Live)) {
					return ErrArtifact
				} else if err != nil {
					return err
				}
			}
		}
		if !classAllowed(d.DataClasses, in.Class, captures) {
			refused = ErrClass
			return s.pushAudit(ctx, tx, c.Actor(), audit.Denied, "export.push_refused", id, map[string]string{
				"destination": d.ID.String(), "class": in.Class, "captures": boolString(captures),
			})
		}
		params := dbq.InsertExportReceiptParams{
			OrgID: c.Org, ID: id, DestinationID: d.ID, Class: in.Class, Streamed: in.Stream, RequestedBy: c.Principal.ID,
			ObjectKey: objectKey(d.KeyPrefix, in.Class, c.Org, id, name),
		}
		if !in.Artifact.IsZero() {
			params.ArtifactID = &in.Artifact
		}
		if in.Class == ClassProofBundles {
			params.FromSeq, params.ToSeq = pgtype.Int8{Int64: in.FromSeq, Valid: true}, pgtype.Int8{Int64: in.ToSeq, Valid: true}
		}
		if err := q.InsertExportReceipt(ctx, params); err != nil {
			return err
		}
		if !in.Stream {
			if s.jobs == nil {
				return errors.New("exports: jobs are unavailable")
			}
			if err := jobs.InsertTx(ctx, s.jobs, tx, PushArgs{Org: c.Org, Receipt: id}, nil); err != nil {
				return err
			}
		}
		if err := s.pushAudit(ctx, tx, c.Actor(), audit.Success, "export.push_requested", id, map[string]string{
			"destination": d.ID.String(), "class": in.Class, "host": hostOf(d.Target), "streamed": boolString(in.Stream),
		}); err != nil {
			return err
		}
		out, err = getReceipt(ctx, q, c.Org, id)
		return err
	})
	if err != nil {
		return Receipt{}, err
	}
	if refused != nil {
		return Receipt{}, refused
	}
	return out, nil
}

// classAllowed is the data-class filter (T-223): the artifact's class, and
// payload_captures too for a pack holding opened captures.
func classAllowed(allowed []string, class string, captures bool) bool {
	has := func(c string) bool {
		for _, a := range allowed {
			if a == c {
				return true
			}
		}
		return false
	}
	return has(class) && (!captures || has(ClassPayloadCaptures))
}

// GetReceipt returns one receipt (siem.read).
func (s *Service) GetReceipt(ctx context.Context, id ids.UUID) (Receipt, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Receipt{}, err
	}
	if err := c.Require(PermRead, td.OrgPath(c.Org)); err != nil {
		return Receipt{}, err
	}
	var out Receipt
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = getReceipt(ctx, dbq.New(tx), c.Org, id)
		return err
	}, db.ReadOnly())
	return out, err
}

// ListReceipts returns one page of receipts, newest first (siem.read); a
// non-zero destination narrows them.
func (s *Service) ListReceipts(ctx context.Context, destination ids.UUID, size int32, token string) ([]Receipt, string, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, "", err
	}
	if err := c.Require(PermRead, td.OrgPath(c.Org)); err != nil {
		return nil, "", err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var after, dest *ids.UUID
	if !pr.After.IsZero() {
		after = &pr.After
	}
	if !destination.IsZero() {
		dest = &destination
	}
	var out []Receipt
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListExportReceipts(ctx, dbq.ListExportReceiptsParams{OrgID: c.Org, DestinationID: dest, AfterID: after, MaxRows: pr.Limit()})
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, receiptOf(dbq.GetExportReceiptRow(r)))
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return nil, "", err
	}
	out, next := page.Finish(pr, out, func(r Receipt) ids.UUID { return r.ID })
	return out, next, nil
}

func getReceipt(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (Receipt, error) {
	r, err := q.GetExportReceipt(ctx, org, id)
	if db.IsNoRows(err) {
		return Receipt{}, ErrReceipt
	} else if err != nil {
		return Receipt{}, err
	}
	return receiptOf(r), nil
}

func receiptOf(r dbq.GetExportReceiptRow) Receipt {
	out := Receipt{
		ID: r.ID, Destination: r.DestinationID, DestinationName: r.DestinationName, Class: r.Class, Artifact: r.ArtifactID, Streamed: r.Streamed,
		RequestedBy: r.RequestedBy, ObjectKey: r.ObjectKey, State: r.State, AbortState: r.AbortState, SizeBytes: r.SizeBytes,
		SHA256: hex.EncodeToString(r.Sha256), Parts: int(r.Parts), Attempts: int(r.Attempts), CreatedAt: r.CreatedAt, StartedAt: r.StartedAt,
		DeliveredAt: r.DeliveredAt, RemovedHereAt: r.RemovedHereAt, NoticeState: r.NoticeState, NoticeSHA256: hex.EncodeToString(r.NoticeSha256),
		NoticeSentAt: r.NoticeSentAt, Status: statusOf(r.State, r.DestinationName, r.RemovedHereAt),
	}
	out.FromSeq, out.ToSeq = r.FromSeq.Int64, r.ToSeq.Int64
	if r.Etag != nil {
		out.ETag = *r.Etag
	}
	if r.LastStatus != nil {
		out.LastStatus = int(*r.LastStatus)
	}
	if r.FailureCode != nil {
		out.FailureCode = *r.FailureCode
	}
	if r.NoticeKey != nil {
		out.NoticeKey = *r.NoticeKey
	}
	return out
}

func (s *Service) pushAudit(ctx context.Context, tx db.TenantTx, a evdomain.Actor, outcome audit.Outcome, name string, id ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: a, Outcome: outcome, Object: &audit.Object{Type: "export_receipt", ID: id.String()}, Details: details,
	})
	return err
}

// upload carries one object: whole when it fits one part, as parts when it
// does not. The object's SHA-256 is computed over the stream.
type upload struct {
	t        transport
	key      string
	partSize int
	// begun stores the upload's id before the first part (HR-516).
	begun func(ctx context.Context, id string) error
	// partBegun stores the highest part number before that part is sent.
	partBegun func(ctx context.Context, number int) error
	buf       []byte
	id        string
	parts     []sent
	number    int
	sum       hash.Hash
	total     int64
}

func newUpload(t transport, key string, partSize int, begun func(context.Context, string) error, partBegun func(context.Context, int) error) *upload {
	return &upload{t: t, key: key, partSize: partSize, begun: begun, partBegun: partBegun, sum: sha256.New()}
}

func (u *upload) write(ctx context.Context, data []byte) error {
	u.sum.Write(data)
	u.total += int64(len(data))
	u.buf = append(u.buf, data...)
	for len(u.buf) >= u.partSize {
		if err := u.part(ctx, u.buf[:u.partSize]); err != nil {
			return err
		}
		u.buf = append(u.buf[:0], u.buf[u.partSize:]...)
	}
	return nil
}

func (u *upload) part(ctx context.Context, body []byte) error {
	if u.id == "" {
		id, err := u.t.Begin(ctx, u.key)
		if err != nil {
			return err
		}
		u.id = id
		if err := u.begun(ctx, id); err != nil {
			return err
		}
	}
	u.number++
	if err := u.partBegun(ctx, u.number); err != nil {
		return err
	}
	s, err := u.t.Part(ctx, u.key, u.id, u.number, body)
	if err != nil {
		return err
	}
	u.parts = append(u.parts, s)
	return nil
}

func (u *upload) finish(ctx context.Context) (sent, error) {
	if u.id == "" {
		return u.t.Put(ctx, u.key, u.buf)
	}
	if len(u.buf) > 0 {
		if err := u.part(ctx, u.buf); err != nil {
			return sent{}, err
		}
		u.buf = nil
	}
	return u.t.Complete(ctx, u.key, u.id, u.parts)
}

// push is one receipt's work: its destination and what was asked.
type push struct {
	org         ids.OrgID
	id          ids.UUID
	destination ids.UUID
	name        string
	target      Target
	classes     []string
	state       string
	class       string
	artifact    *ids.UUID
	streamed    bool
	from, to    int64
	requestedBy ids.UUID
	key         string
	receipt     string
	uploadID    string
	parts       int
	abort       string
	t           transport
}

// final is a failure no retry can change.
func final(code string) error { return pushError{Code: code, Final: true} }

func (s *Service) transportOf(ctx context.Context, org ids.OrgID, destination ids.UUID, t Target, blob []byte) (transport, error) {
	plain, err := s.envelope.Decrypt(ctx, s.field(org, destination), SecretPurpose, blob)
	if err != nil {
		return nil, fmt.Errorf("exports: decrypt credential: %w", err)
	}
	var c sealedCredential
	if err := json.Unmarshal(plain, &c); err != nil {
		return nil, fmt.Errorf("exports: read credential: %w", err)
	}
	base, err := t.Base()
	if err != nil {
		return nil, err
	}
	client := s.public
	if t.Internal {
		client = s.internal
	}
	return s.newTransport(t, client, base, c), nil
}

func (s *Service) newTransport(t Target, client *http.Client, base *url.URL, c sealedCredential) transport {
	if t.Kind == KindS3 {
		return &s3Transport{
			client: client, base: base, signer: sigv4.Signer{Region: t.Region, Service: "s3", S3: true},
			creds: sigv4.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey}, now: s.clock.Now,
		}
	}
	return &putTransport{client: client, base: base, token: c.BearerToken}
}

func (s *Service) load(ctx context.Context, org ids.OrgID, id ids.UUID) (*push, error) {
	var p *push
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).LoadExportPush(ctx, org, id)
		if db.IsNoRows(err) {
			return ErrReceipt
		} else if err != nil {
			return err
		}
		tg := Target{Kind: r.Kind, URL: r.Url, KeyPrefix: r.KeyPrefix, PathStyle: r.PathStyle, Internal: r.Internal}
		if r.Bucket != nil {
			tg.Bucket = *r.Bucket
		}
		if r.Region != nil {
			tg.Region = *r.Region
		}
		p = &push{
			org: org, id: id, destination: r.DestinationID, name: r.Name, target: tg, classes: r.DataClasses, state: r.DestinationState, class: r.Class,
			artifact: r.ArtifactID, streamed: r.Streamed, requestedBy: r.RequestedBy, key: r.ObjectKey, receipt: r.ReceiptState, abort: r.AbortState,
		}
		p.from, p.to = r.FromSeq.Int64, r.ToSeq.Int64
		if r.UploadID != nil && r.AbortState == "PENDING" {
			p.uploadID = *r.UploadID
			p.parts = int(r.Parts)
		}
		p.t, err = s.transportOf(ctx, org, r.DestinationID, tg, r.Secret)
		return err
	})
	return p, err
}

// authority returns the requester's caller with their live bindings: a
// push queued by someone who has since lost the right does not go out.
func (s *Service) authority(ctx context.Context, tx db.TenantTx, p *push) (tenancy.Caller, error) {
	q := dbq.New(tx)
	u, err := q.GetUser(ctx, p.org, p.requestedBy)
	if err != nil {
		return tenancy.Caller{}, err
	}
	if u.State != "ACTIVE" {
		return tenancy.Caller{}, final("authority_lost")
	}
	principal := td.PrincipalRef{Kind: td.KindUser, ID: u.ID}
	bs, err := tenancy.Bindings(ctx, q, p.org, principal)
	if err != nil {
		return tenancy.Caller{}, err
	}
	c := tenancy.Caller{Subject: td.Subject{Org: p.org, Principal: principal, Bindings: bs}}
	for _, perm := range append(classPermissions(p.class), PermManage) {
		if !c.Can(perm, td.OrgPath(p.org)) {
			return tenancy.Caller{}, final("authority_lost")
		}
	}
	return c, nil
}

// gate is what must still hold when a push starts: the destination active,
// its target allowed, the licence, the requester's authority. A person who
// paused the destination, a rule that changed or a lapsed licence stops
// what is queued.
func (s *Service) gate(ctx context.Context, p *push) (tenancy.Caller, error) {
	if p.state != StateActive {
		return tenancy.Caller{}, final("destination_not_active")
	}
	if err := CheckTarget(p.target, s.ownHost, s.cfg.AllowedPrivateRanges); err != nil {
		return tenancy.Caller{}, final("target_refused")
	}
	if err := s.business(ctx); err != nil {
		return tenancy.Caller{}, final("edition_lapsed")
	}
	var c tenancy.Caller
	err := s.pool.InTenantTx(ctx, p.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		c, err = s.authority(ctx, tx, p)
		return err
	}, db.ReadOnly())
	return c, err
}

func (s *Service) newUploadFor(p *push) *upload {
	update := func(ctx context.Context, f func(q *dbq.Queries) (int64, error)) error {
		return s.pool.InTenantTx(ctx, p.org, func(ctx context.Context, tx db.TenantTx) error {
			n, err := f(dbq.New(tx))
			if err == nil && n == 0 {
				return db.ErrLostRace
			}
			return err
		})
	}
	return newUpload(p.t, p.key, s.partSize, func(ctx context.Context, id string) error {
		p.uploadID, p.parts = id, 0
		return update(ctx, func(q *dbq.Queries) (int64, error) { return q.SetExportUpload(ctx, &id, p.org, p.id) })
	}, func(ctx context.Context, number int) error {
		p.parts = number
		return update(ctx, func(q *dbq.Queries) (int64, error) {
			return q.SetExportPartBegun(ctx, int32(number), p.org, p.id) //nolint:gosec // G115: at most 10000 parts
		})
	})
}

// abortUpload ends a failed upload, whatever happened to the push: its
// context may be gone, so it runs on its own (HR-516). An abort that still
// fails stays PENDING and the sweep tries again.
func (s *Service) abortUpload(ctx context.Context, p *push) bool {
	if p.uploadID == "" {
		return true
	}
	var err error
	for range abortAttempts {
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), abortTimeout)
		err = p.t.Abort(actx, p.key, p.uploadID, p.parts)
		cancel()
		if err == nil {
			break
		}
	}
	if err != nil {
		s.log.WarnContext(ctx, "exports.abort_failed", slog.String("receipt", p.id.String()), pclog.Err(err))
		return false
	}
	if err := s.pool.InTenantTx(context.WithoutCancel(ctx), p.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).SetExportAborted(ctx, p.org, p.id)
		return err
	}); err != nil {
		s.log.WarnContext(ctx, "exports.abort_unrecorded", slog.String("receipt", p.id.String()), pclog.Err(err))
		return false
	}
	p.uploadID = ""
	return true
}

// Run pushes one stored artifact. last is the job's last attempt: its
// failure is the receipt's. Every outcome lands on the receipt (HR-514).
func (s *Service) Run(ctx context.Context, org ids.OrgID, id ids.UUID, last bool) error {
	p, err := s.load(ctx, org, id)
	if err != nil {
		return err
	}
	if p.receipt != ReceiptQueued || p.streamed {
		return nil
	}
	// An abort that failed on an earlier attempt comes first: a new upload's
	// id would replace the one it still has to end (HR-516).
	if !s.abortUpload(ctx, p) {
		cause := pushError{Code: "abort_pending"}
		if !last {
			return cause
		}
		return s.settleFailure(ctx, p, cause, true)
	}
	started := false
	if err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		n, err := dbq.New(tx).StartExportPush(ctx, org, id)
		started = n == 1
		return err
	}); err != nil || !started {
		return err
	}
	u := s.newUploadFor(p)
	res, err := s.send(ctx, p, u)
	if err != nil {
		s.abortUpload(ctx, p)
		last = last || isFinal(err)
		if serr := s.settleFailure(ctx, p, err, last); serr != nil {
			return errors.Join(err, serr)
		}
		if last {
			return nil
		}
		return err
	}
	return s.settle(ctx, p, u, res)
}

func isFinal(err error) bool {
	var p pushError
	return errors.As(err, &p) && p.Final
}

func (s *Service) send(ctx context.Context, p *push, u *upload) (sent, error) {
	c, err := s.gate(ctx, p)
	if err != nil {
		return sent{}, err
	}
	switch p.class {
	case ClassEvidencePacks:
		return s.sendPack(ctx, p, u)
	case ClassProofBundles:
		e, err := s.bundles.ExportBundle(tenancy.WithCaller(ctx, c), evapp.Selection{From: p.from, To: p.to}, 0)
		if err != nil {
			return sent{}, fmt.Errorf("exports: build bundle: %w", err)
		}
		if err := u.write(ctx, e.Bundle); err != nil {
			return sent{}, err
		}
		return u.finish(ctx)
	case ClassOrgExports:
		return s.sendExport(ctx, p, u)
	}
	return sent{}, final("unknown_class")
}

func (s *Service) sendPack(ctx context.Context, p *push, u *upload) (sent, error) {
	var pack dbq.GetPackForPushRow
	err := s.pool.InTenantTx(ctx, p.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		pack, err = dbq.New(tx).GetPackForPush(ctx, p.org, *p.artifact)
		return err
	}, db.ReadOnly())
	if db.IsNoRows(err) {
		return sent{}, final("artifact_gone")
	} else if err != nil {
		return sent{}, err
	}
	if pack.State != "READY" || !pack.Live {
		return sent{}, final("artifact_gone")
	}
	if !classAllowed(p.classes, p.class, pack.Captures) {
		return sent{}, final("class_refused")
	}
	if err := u.write(ctx, pack.Content); err != nil {
		return sent{}, err
	}
	return u.finish(ctx)
}

// ManifestSuffix names the signed manifest next to a pushed export: the
// object is the export's archive parts in order, and the manifest says
// where each starts and its SHA-256.
const ManifestSuffix = ".manifest.jws"

// sendExport pushes a ready export, one stored part at a time.
func (s *Service) sendExport(ctx context.Context, p *push, u *upload) (sent, error) {
	var r dbq.GetExportForPushRow
	err := s.pool.InTenantTx(ctx, p.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		r, err = dbq.New(tx).GetExportForPush(ctx, p.org, *p.artifact)
		return err
	}, db.ReadOnly())
	if db.IsNoRows(err) {
		return sent{}, final("artifact_gone")
	} else if err != nil {
		return sent{}, err
	}
	if r.State != "READY" || r.Parts == 0 || !r.Live || r.Manifest == nil {
		return sent{}, final("artifact_gone")
	}
	for n := int32(1); n <= r.Parts; n++ {
		var content []byte
		err := s.pool.InTenantTx(ctx, p.org, func(ctx context.Context, tx db.TenantTx) error {
			part, err := dbq.New(tx).GetDataRequestPart(ctx, p.org, *p.artifact, n)
			content = part.Content
			return err
		}, db.ReadOnly())
		if db.IsNoRows(err) {
			return sent{}, final("artifact_gone")
		} else if err != nil {
			return sent{}, err
		}
		if err := u.write(ctx, content); err != nil {
			return sent{}, err
		}
	}
	// The manifest goes first: a failure then leaves nothing whole at the
	// destination, and a whole object always has its manifest.
	if _, err := p.t.Put(ctx, p.key+ManifestSuffix, []byte(*r.Manifest)); err != nil {
		return sent{}, err
	}
	return u.finish(ctx)
}

// settle records a delivery.
func (s *Service) settle(ctx context.Context, p *push, u *upload, res sent) error {
	parts := len(u.parts)
	if parts == 0 {
		parts = 1
	}
	sum := u.sum.Sum(nil)
	return s.pool.InTenantTx(context.WithoutCancel(ctx), p.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		status := int32(res.Status) //nolint:gosec // G115: an HTTP status
		n, err := q.DeliverExportReceipt(ctx, dbq.DeliverExportReceiptParams{
			OrgID: p.org, ID: p.id, SizeBytes: u.total, Sha256: sum, Parts: int32(parts), //nolint:gosec // G115: at most 10000 parts
			Etag: optional(res.ETag), LastStatus: &status,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return db.ErrLostRace
		}
		if err := q.RecordExportDelivered(ctx, p.org, p.destination); err != nil {
			return err
		}
		return s.pushAudit(ctx, tx, Actor, audit.Success, "export.push_delivered", p.id, map[string]string{
			"destination": p.destination.String(), "class": p.class, "object_key": p.key, "size_bytes": strconv.FormatInt(u.total, 10),
			"sha256": hex.EncodeToString(sum), "parts": strconv.Itoa(parts),
		})
	})
}

// settleFailure records a failed attempt, and with last the failed push.
func (s *Service) settleFailure(ctx context.Context, p *push, cause error, last bool) error {
	code, status := failureOf(cause)
	s.log.WarnContext(ctx, "exports.push_failed", slog.String("receipt", p.id.String()), slog.String("code", code))
	return s.pool.InTenantTx(context.WithoutCancel(ctx), p.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var st *int32
		if status != 0 {
			v := int32(status) //nolint:gosec // G115: an HTTP status
			st = &v
		}
		var err error
		if last {
			_, err = q.FailExportReceipt(ctx, dbq.FailExportReceiptParams{FailureCode: &code, LastStatus: st, OrgID: p.org, ID: p.id})
		} else {
			_, err = q.RetryExportReceipt(ctx, dbq.RetryExportReceiptParams{FailureCode: &code, LastStatus: st, OrgID: p.org, ID: p.id})
		}
		if err != nil {
			return err
		}
		if err := s.recordFailure(ctx, tx, p.org, p.destination, p.name, code); err != nil {
			return err
		}
		if !last {
			return nil
		}
		return s.pushAudit(ctx, tx, Actor, audit.Failure, "export.push_failed", p.id, map[string]string{
			"destination": p.destination.String(), "class": p.class, "code": code,
		})
	})
}

func (s *Service) recordFailure(ctx context.Context, tx db.TenantTx, org ids.OrgID, destination ids.UUID, name, code string) error {
	r, err := dbq.New(tx).RecordExportFailure(ctx, &code, org, destination)
	if err != nil {
		return err
	}
	if s.failures == nil || ndomain.HealthOf(int(r.ConsecutiveFailures)) != ndomain.Failing || r.FailingSince == nil {
		return nil
	}
	_, err = s.failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
		Org: org, Kind: FailureKind,
		Summary:   "Pushes to export destination " + name + " have failed " + strconv.Itoa(int(r.ConsecutiveFailures)) + " times in a row (" + code + ").",
		NextStep:  "Check the destination and its credential; receipts show which pushes did not arrive.",
		Scope:     []reflexdomain.Subject{{Type: reflexdomain.SubjectResource, ID: "export_destination:" + destination.String()}},
		DedupeKey: FailureKind + ":" + destination.String() + ":" + strconv.FormatInt(r.FailingSince.Unix(), 10),
	})
	return err
}

// PushArgs asks for one receipt's push. Job args carry ids only (HR-056).
type PushArgs struct {
	Org     ids.OrgID `json:"org"`
	Receipt ids.UUID  `json:"receipt"`
}

// Kind implements river.JobArgs.
func (PushArgs) Kind() string { return "exports.push" }

// InsertOpts runs a push a few times, on the notifications queue: slow
// destinations never hold up other jobs.
func (PushArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: napp.Queue, MaxAttempts: pushAttempts}
}

type pushWorker struct {
	river.WorkerDefaults[PushArgs]
	svc *Service
}

func (w *pushWorker) Timeout(*river.Job[PushArgs]) time.Duration { return pushTimeout }

func (w *pushWorker) Work(ctx context.Context, job *river.Job[PushArgs]) error {
	return w.svc.Run(ctx, job.Args.Org, job.Args.Receipt, job.Attempt >= job.MaxAttempts)
}

// Stream is one export streaming to a destination while it builds. The
// build's transaction cannot wait on the network (the idle timeout ends
// it), so a goroutine uploads and Write keeps the transaction alive while
// it waits for that goroutine.
type Stream struct {
	s    *Service
	p    *push
	u    *upload
	ops  chan streamOp
	quit chan struct{}
	done chan struct{}
	once sync.Once
	err  error
}

type streamOp struct {
	data     []byte
	finish   bool
	manifest []byte
}

// Open claims the receipt a person left waiting for this export. Without
// one, or when the destination can no longer take it, the export builds as
// usual: nil, nil, and a claimed receipt says why it failed.
func (s *Service) Open(ctx context.Context, org ids.OrgID, request, requestedBy ids.UUID) (*Stream, error) {
	var id ids.UUID
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		id, err = dbq.New(tx).ClaimStreamedExportReceipt(ctx, dbq.ClaimStreamedExportReceiptParams{
			RequestID: &request, OrgID: org, RequestedBy: requestedBy, WaitSeconds: int32(StreamWait / time.Second),
		})
		return err
	})
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	p, err := s.load(ctx, org, id)
	if err != nil {
		return nil, err
	}
	if _, err := s.gate(ctx, p); err != nil {
		if serr := s.settleFailure(ctx, p, err, true); serr != nil {
			return nil, errors.Join(err, serr)
		}
		return nil, nil
	}
	st := &Stream{s: s, p: p, u: s.newUploadFor(p), ops: make(chan streamOp), quit: make(chan struct{}), done: make(chan struct{})}
	go st.run(ctx)
	return st, nil
}

func (st *Stream) run(ctx context.Context) {
	defer close(st.done)
	var err error
	finished := false
	var res sent
loop:
	for {
		select {
		case <-st.quit:
			err = pushError{Code: "build_failed"}
			break loop
		case <-ctx.Done():
			err = ctx.Err()
			break loop
		case op := <-st.ops:
			if !op.finish {
				if err = st.u.write(ctx, op.data); err != nil {
					break loop
				}
				continue
			}
			if _, err = st.p.t.Put(ctx, st.p.key+ManifestSuffix, op.manifest); err != nil {
				break loop
			}
			if res, err = st.u.finish(ctx); err != nil {
				break loop
			}
			finished = true
			break loop
		}
	}
	if finished {
		st.err = st.s.settle(ctx, st.p, st.u, res)
		return
	}
	st.err = err
	st.s.abortUpload(ctx, st.p)
	if serr := st.s.settleFailure(ctx, st.p, err, true); serr != nil {
		st.err = errors.Join(err, serr)
	}
}

// send hands op to the uploader, keeping the caller's transaction alive.
func (st *Stream) send(ctx context.Context, op streamOp, keepAlive func(context.Context) error) error {
	tick := time.NewTicker(keepAliveEvery)
	defer tick.Stop()
	for {
		select {
		case st.ops <- op:
			return nil
		case <-st.done:
			if st.err != nil {
				return st.err
			}
			return errors.New("exports: the stream has ended")
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			if err := keepAlive(ctx); err != nil {
				return err
			}
		}
	}
}

// Write hands an archive part to the uploader.
func (st *Stream) Write(ctx context.Context, part []byte, keepAlive func(context.Context) error) error {
	return st.send(ctx, streamOp{data: bytes.Clone(part)}, keepAlive)
}

// Finish completes the upload, pushes the signed manifest and records the
// receipt. The export is whole at the destination when it returns nil.
func (st *Stream) Finish(ctx context.Context, manifest string, keepAlive func(context.Context) error) error {
	if err := st.send(ctx, streamOp{finish: true, manifest: []byte(manifest)}, keepAlive); err != nil {
		return err
	}
	tick := time.NewTicker(keepAliveEvery)
	defer tick.Stop()
	for {
		select {
		case <-st.done:
			return st.err
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			if err := keepAlive(ctx); err != nil {
				return err
			}
		}
	}
}

// Abort stops a stream that did not finish: the build failed. It runs the
// multipart abort and returns when that is done (HR-516). After Finish it
// does nothing.
func (st *Stream) Abort() {
	st.once.Do(func() { close(st.quit) })
	<-st.done
}
