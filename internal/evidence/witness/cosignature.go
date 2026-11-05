// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package witness implements the client side of C2SP transparency-log
// witnessing for the deployment-wide root log (G0 M35 D1041, HR-782,
// HR-783): Ed25519 cosignatures (c2sp.org/tlog-cosignature, cosignature/v1)
// with their verifier keys in the c2sp.org/signed-note vkey form, and the
// add-checkpoint request of c2sp.org/tlog-witness. It uses only the
// standard library and the note package.
//
// A cosignature is a signed-note signature line by the witness's key name
// whose signature is the 8-byte big-endian UNIX time of the cosignature
// followed by the Ed25519 signature over
//
//	cosignature/v1
//	time <time>
//	<the checkpoint body>
//
// and whose key ID is the first four bytes of SHA-256(key name ‖ 0x0A ‖
// 0x04 ‖ the 32-byte public key).
package witness

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/note"
)

// TypeCosignature is the signature type of cosignature/v1 Ed25519 keys.
const TypeCosignature = 0x04

// cosignatureHeader starts every cosigned message.
const cosignatureHeader = "cosignature/v1\n"

// timestampSize is the length of the timestamp that precedes the signature.
const timestampSize = 8

// ErrInvalidVKey reports a verifier key that is not a cosignature/v1 key.
var ErrInvalidVKey = errors.New("witness: invalid cosignature verifier key")

// KeyID returns the key ID of a cosignature/v1 key named name.
func KeyID(name string, pub ed25519.PublicKey) uint32 {
	return note.KeyID(name, []byte{TypeCosignature}, pub)
}

// Message returns what a witness signs at t over a checkpoint's note text.
func Message(t time.Time, checkpointText string) []byte {
	return []byte(cosignatureHeader + "time " + strconv.FormatInt(t.Unix(), 10) + "\n" + checkpointText)
}

// Verifier checks the cosignatures of one witness key. It is a note.Verifier
// over the checkpoint text, so a cosigned note opens with note.Open.
type Verifier struct {
	name string
	id   uint32
	pub  ed25519.PublicKey
}

var _ note.Verifier = (*Verifier)(nil)

// Name is the witness's key name.
func (v *Verifier) Name() string { return v.name }

// KeyID is the witness key's ID.
func (v *Verifier) KeyID() uint32 { return v.id }

// Verify checks sig (timestamp ‖ Ed25519 signature) over msg, the
// checkpoint text.
func (v *Verifier) Verify(msg, sig []byte) bool {
	t, ok := v.Time(sig)
	if !ok {
		return false
	}
	return ed25519.Verify(v.pub, Message(t, string(msg)), sig[timestampSize:])
}

// Time returns the timestamp of a cosignature's signature bytes.
func (v *Verifier) Time(sig []byte) (time.Time, bool) {
	if len(sig) != timestampSize+ed25519.SignatureSize {
		return time.Time{}, false
	}
	ts := binary.BigEndian.Uint64(sig[:timestampSize])
	if ts > uint64(1)<<62 {
		return time.Time{}, false
	}
	return time.Unix(int64(ts), 0).UTC(), true //nolint:gosec // G115: bounded above
}

// VKey encodes the verifier key: <name>+<hex key ID>+<base64(0x04 ‖ key)>.
func (v *Verifier) VKey() string {
	return v.name + "+" + fmt.Sprintf("%08x", v.id) + "+" + base64.StdEncoding.EncodeToString(append([]byte{TypeCosignature}, v.pub...))
}

// NewVerifier returns the verifier of an Ed25519 cosignature key.
func NewVerifier(name string, pub ed25519.PublicKey) (*Verifier, error) {
	if !note.ValidKeyName(name) || len(pub) != ed25519.PublicKeySize {
		return nil, ErrInvalidVKey
	}
	pub = append(ed25519.PublicKey(nil), pub...)
	return &Verifier{name: name, id: KeyID(name, pub), pub: pub}, nil
}

// ParseVKey parses a cosignature/v1 verifier key and checks its key ID.
func ParseVKey(vkey string) (*Verifier, error) {
	name, rest, ok := strings.Cut(strings.TrimSpace(vkey), "+")
	if !ok {
		return nil, ErrInvalidVKey
	}
	idHex, keyB64, ok := strings.Cut(rest, "+")
	if !ok || len(idHex) != 8 {
		return nil, ErrInvalidVKey
	}
	idRaw, err := hex.DecodeString(idHex)
	if err != nil {
		return nil, ErrInvalidVKey
	}
	key, err := base64.StdEncoding.Strict().DecodeString(keyB64)
	if err != nil || len(key) != 1+ed25519.PublicKeySize || key[0] != TypeCosignature {
		return nil, fmt.Errorf("%w: only Ed25519 cosignature/v1 keys (type 0x04) are accepted", ErrInvalidVKey)
	}
	v, err := NewVerifier(name, ed25519.PublicKey(key[1:]))
	if err != nil {
		return nil, err
	}
	if v.id != binary.BigEndian.Uint32(idRaw) {
		return nil, fmt.Errorf("%w: the key ID does not match the key", ErrInvalidVKey)
	}
	return v, nil
}

// Cosignature is one verified cosignature line.
type Cosignature struct {
	Witness string    // the witness's key name
	KeyID   uint32    // its key ID
	Time    time.Time // when it cosigned
	Line    string    // the signature line, without its newline
}

// ParseCosignatures reads the signature lines a witness returned for a
// checkpoint (text, the checkpoint body) and keeps those of v that verify.
// A line of v that does not verify is an error; lines of other keys are
// ignored, as the signed-note spec asks. At least one line of v is needed.
func ParseCosignatures(body []byte, text string, v *Verifier) ([]Cosignature, error) {
	if len(body) > note.MaxNoteBytes {
		return nil, errors.New("witness: response too large")
	}
	// The lines are a note's signature block: put them under the checkpoint
	// text and open it as a note with v as the only known key.
	msg := append([]byte(text+"\n"), body...)
	if len(body) == 0 || body[len(body)-1] != '\n' {
		msg = append(msg, '\n')
	}
	_, verified, err := note.Open(msg, v)
	if err != nil {
		return nil, fmt.Errorf("witness %s: %w", v.name, err)
	}
	out := make([]Cosignature, 0, len(verified))
	for _, s := range verified {
		t, ok := v.Time(s.Sig)
		if !ok {
			return nil, fmt.Errorf("witness %s: malformed cosignature", v.name)
		}
		out = append(out, Cosignature{Witness: s.Name, KeyID: s.KeyID, Time: t, Line: signatureLine(s)})
	}
	return out, nil
}

// signatureLine encodes a note signature line without its newline.
func signatureLine(s note.Signature) string {
	b := make([]byte, 4+len(s.Sig))
	binary.BigEndian.PutUint32(b, s.KeyID)
	copy(b[4:], s.Sig)
	return "— " + s.Name + " " + base64.StdEncoding.EncodeToString(b)
}

// AppendLines returns the signed note with extra signature lines appended:
// a checkpoint together with its cosignatures, which verifiers that know
// only the log's key still open.
func AppendLines(signed []byte, lines []string) []byte {
	out := append([]byte(nil), signed...)
	for _, l := range lines {
		out = append(out, l...)
		out = append(out, '\n')
	}
	return out
}
