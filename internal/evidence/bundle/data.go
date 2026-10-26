// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// MaxDataDocumentBytes bounds a signed export manifest or deletion record.
const MaxDataDocumentBytes = 1 << 20

const dataPartBytes = 64 << 20

const dataLimits = "This checks signed statements and exported bytes against pinned keys. It does not prove export completeness, physical erasure, backup expiry, or an external effect."

type dataPart struct {
	Number int32  `json:"number"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type dataFile struct {
	Path   string `json:"path"`
	Part   int32  `json:"part"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type dataProjection struct {
	Table   string   `json:"table"`
	Columns []string `json:"columns"`
}

type exportDocument struct {
	Format          string           `json:"format"`
	RegistryVersion int              `json:"registry_version"`
	Org             string           `json:"org"`
	Request         string           `json:"request"`
	CreatedAt       time.Time        `json:"created_at"`
	ExpiresAt       time.Time        `json:"expires_at"`
	LedgerThrough   int64            `json:"ledger_through"`
	Projections     []dataProjection `json:"projections"`
	Excluded        []string         `json:"excluded"`
	Parts           []dataPart       `json:"parts"`
	Files           []dataFile       `json:"files"`
	Cosign          *pack.Cosign     `json:"mldsa,omitzero"`
}

type deletionDocument struct {
	Format             string    `json:"format"`
	Org                string    `json:"org"`
	Request            string    `json:"request"`
	Reason             string    `json:"reason"`
	RequestedByAccount string    `json:"requested_by_account,omitzero"`
	RequestTime        time.Time `json:"request_time"`
	WindowEndTime      time.Time `json:"window_end_time"`
	StartTime          time.Time `json:"start_time"`
	CompleteTime       time.Time `json:"complete_time"`
	Tables             []struct {
		Table string `json:"table"`
		Rows  int64  `json:"rows"`
	} `json:"tables"`
	Verified         bool      `json:"verified"`
	BackupExpireTime time.Time `json:"backup_expire_time"`
	ReappliedFrom    string    `json:"reapplied_from,omitzero"`
	ReappliedKind    string    `json:"reapplied_kind,omitzero"`
}

func dataSignature(raw []byte, typ, purpose string, created time.Time, o Options) (pack.Signed, error) {
	if len(raw) > MaxDataDocumentBytes || o.Trust == nil {
		return pack.Signed{}, errors.New("bounded data document and pinned trust are required")
	}
	s, err := pack.ParseDataJWS(string(raw), typ)
	if err != nil {
		return s, err
	}
	k := o.Trust.key(purpose, s.Kid)
	if k == nil || !s.Verify(k.ed) || !k.ValidAt(created) {
		return s, errors.New("signature or signing-key validity failed")
	}
	return s, nil
}

func validDataID(s string) bool {
	u, err := ids.ParseUUID(s)
	return err == nil && !u.IsZero() && u.String() == s
}

func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}

var dataName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
var tableFile = regexp.MustCompile(`^tables/([a-z][a-z0-9_]{0,62})/[0-9]{6}\.jsonl$`)
var evidenceFile = regexp.MustCompile(`^evidence/[0-9]{6}\.json$`)

// VerifyExport checks a signed manifest, every ZIP part and each embedded
// evidence bundle offline. Part files are named part-001.zip, part-002.zip, ...
// No archive is extracted. Reads are bounded and CRCs/digests are checked.
func VerifyExport(raw []byte, parts fs.FS, o Options) *Report {
	r := newReport()
	r.Limits = dataLimits
	s, err := pack.ParseDataJWS(string(raw), "pap-export+jwt")
	var m exportDocument
	if err == nil && len(raw) <= MaxDataDocumentBytes {
		err = json.Unmarshal(s.Payload, &m, json.RejectUnknownMembers(true))
	}
	if err == nil && (m.Format != "pantherclaw.export/v1" || m.RegistryVersion != 1 || !validDataID(m.Org) || !validDataID(m.Request) || m.CreatedAt.IsZero() || !m.ExpiresAt.After(m.CreatedAt) || m.ExpiresAt.Sub(m.CreatedAt) > 7*24*time.Hour || m.LedgerThrough < 0 || len(m.Parts) < 1 || len(m.Parts) > 64 || len(m.Files) == 0 || len(m.Files) > 20000) {
		err = errors.New("invalid export manifest shape")
	}
	if err == nil {
		s, err = dataSignature(raw, "pap-export+jwt", PurposeEvidencePacks, m.CreatedAt, o)
	}
	if err != nil {
		r.add("export.manifest", "", Failed, "%v", err)
		return r
	}
	r.add("export.manifest", m.Org, Passed, "signed registry v1; ledger through %d; download window %s to %s", m.LedgerThrough, m.CreatedAt.Format(time.RFC3339), m.ExpiresAt.Format(time.RFC3339))
	if m.Cosign != nil {
		c := m.Cosign
		m.Cosign = nil
		unsigned, marshalErr := pack.Canonical(m)
		k := o.Trust.key(PurposeCheckpointsPQ, c.Kid)
		if marshalErr != nil || c.Algorithm != AlgMLDSA65 || k == nil || !k.ValidAt(m.CreatedAt) || len(c.Signature) != mldsa.MLDSA65SignatureSize || mldsa.Verify(k.mldsa, unsigned, c.Signature, &mldsa.Options{Context: "pantherclaw.export/v1"}) != nil {
			r.add("export.cosignature", "", Failed, "ML-DSA-65 co-signature failed or key is not pinned")
		} else {
			r.add("export.cosignature", c.Kid, Passed, "ML-DSA-65 signature verifies")
		}
	} else {
		r.add("export.cosignature", "", NotAvailable, "no ML-DSA-65 co-signature")
	}
	projections := map[string]map[string]bool{}
	for _, p := range m.Projections {
		if !dataName.MatchString(p.Table) || projections[p.Table] != nil || len(p.Columns) == 0 {
			r.add("export.scope", "", Failed, "invalid or duplicate table projection")
			return r
		}
		columns := map[string]bool{}
		for _, col := range p.Columns {
			if !dataName.MatchString(col) || columns[col] {
				r.add("export.scope", p.Table, Failed, "invalid or duplicate column")
				return r
			}
			columns[col] = true
		}
		projections[p.Table] = columns
	}
	files := map[string]dataFile{}
	var total int64
	for _, f := range m.Files {
		if files[f.Path].Path != "" || f.Part < 1 || int(f.Part) > len(m.Parts) || f.Size < 0 || f.Size > dataPartBytes || !validDigest(f.SHA256) || (!tableFile.MatchString(f.Path) && !evidenceFile.MatchString(f.Path)) {
			r.add("export.files", "", Failed, "invalid file declaration")
			return r
		}
		files[f.Path] = f
	}
	seen := map[string]bool{}
	for i, part := range m.Parts {
		name := fmt.Sprintf("part-%03d.zip", i+1)
		total += part.Size
		if part.Number != int32(i+1) || part.Size < 1 || part.Size > dataPartBytes || total > 2<<30 || !validDigest(part.SHA256) {
			r.add("export.part", name, Failed, "invalid part declaration")
			return r
		}
		err := verifyDataPart(parts, name, part, files, seen, projections, m.Org, o, r)
		if err != nil {
			r.add("export.part", name, Failed, "%v", err)
			return r
		}
		r.add("export.part", name, Passed, "size, SHA-256, ZIP contents and declared file digests match")
	}
	if len(seen) != len(files) {
		r.add("export.files", "", Failed, "one or more declared files are missing")
	}
	return r
}

func verifyDataPart(parts fs.FS, name string, part dataPart, files map[string]dataFile, seen map[string]bool, projections map[string]map[string]bool, org string, o Options, r *Report) error {
	if parts == nil {
		return errors.New("parts directory is required")
	}
	f, err := parts.Open(name)
	if err != nil {
		return err
	}
	b, readErr := io.ReadAll(io.LimitReader(f, part.Size+1))
	closeErr := f.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	h := sha256.Sum256(b)
	if int64(len(b)) != part.Size || hex.EncodeToString(h[:]) != part.SHA256 {
		return errors.New("part size or SHA-256 mismatch")
	}
	z, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return err
	}
	for _, item := range z.File {
		declared, ok := files[item.Name]
		if !ok || seen[item.Name] || declared.Part != part.Number || item.Method != zip.Store || item.Mode()&fs.ModeType != 0 || item.UncompressedSize64 != uint64(declared.Size) {
			return errors.New("unlisted, duplicate, unsafe or mismatched ZIP entry")
		}
		reader, err := item.Open()
		if err != nil {
			return err
		}
		content, readErr := io.ReadAll(io.LimitReader(reader, declared.Size+1))
		closeErr := reader.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return err
		}
		digest := sha256.Sum256(content)
		if int64(len(content)) != declared.Size || hex.EncodeToString(digest[:]) != declared.SHA256 {
			return errors.New("file size, CRC or SHA-256 mismatch")
		}
		if match := tableFile.FindStringSubmatch(item.Name); match != nil {
			columns := projections[match[1]]
			if columns == nil {
				return errors.New("table is outside declared projection")
			}
			scanner := bufio.NewScanner(bytes.NewReader(content))
			scanner.Buffer(make([]byte, 4096), dataPartBytes)
			for scanner.Scan() {
				var row map[string]jsontext.Value
				if err := json.Unmarshal(scanner.Bytes(), &row); err != nil || row == nil {
					return errors.New("invalid table JSONL row")
				}
				for col := range row {
					if !columns[col] {
						return errors.New("row contains undeclared column")
					}
				}
			}
			if err := scanner.Err(); err != nil {
				return err
			}
		} else {
			bundle, err := Decode(content)
			if err != nil {
				return err
			}
			if bundle.Org != org {
				return errors.New("evidence bundle belongs to another organisation")
			}
			sub := Verify(bundle, o)
			for _, check := range sub.Checks {
				r.add("export.evidence."+check.Name, item.Name, check.Status, "%s", check.Detail)
			}
		}
		seen[item.Name] = true
	}
	return nil
}

// VerifyDeletion verifies a signed completion record, not an erasure intent.
// The server's verified flag is an authenticated claim, not independent proof
// of physical storage erasure or expiry of every backup.
func VerifyDeletion(raw []byte, o Options) *Report {
	r := newReport()
	r.Limits = dataLimits
	s, err := pack.ParseDataJWS(string(raw), "pap-deletion+jwt")
	var m deletionDocument
	if err == nil && len(raw) <= MaxDataDocumentBytes {
		err = json.Unmarshal(s.Payload, &m, json.RejectUnknownMembers(true))
	}
	if err == nil && (m.Format != "pantherclaw.deletion/v1" || !validDataID(m.Org) || !validDataID(m.Request) || !m.Verified || (m.Reason != "requested" && m.Reason != "lapse_90d") || m.RequestTime.IsZero() || m.WindowEndTime.Before(m.RequestTime) || m.StartTime.Before(m.WindowEndTime) || m.CompleteTime.Before(m.StartTime) || m.BackupExpireTime.Before(m.CompleteTime) || (m.RequestedByAccount != "" && !validDataID(m.RequestedByAccount)) || (m.ReappliedFrom != "" && !validDigest(m.ReappliedFrom))) {
		err = errors.New("invalid or incomplete deletion record")
	}
	if err == nil {
		_, err = dataSignature(raw, "pap-deletion+jwt", PurposeReceipts, m.CompleteTime, o)
	}
	seen := map[string]bool{}
	for _, table := range m.Tables {
		if !dataName.MatchString(table.Table) || seen[table.Table] || table.Rows < 0 {
			err = errors.New("invalid deletion table counts")
		}
		seen[table.Table] = true
	}
	if err != nil {
		r.add("deletion.record", "", Failed, "%v", err)
		return r
	}
	r.add("deletion.signature", m.Org, Passed, "signed completion record for request %s", m.Request)
	r.add("deletion.claim", "", Passed, "server reports verified deletion at %s; configured backup expiry %s", m.CompleteTime.Format(time.RFC3339), m.BackupExpireTime.Format(time.RFC3339))
	return r
}
