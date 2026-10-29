// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/detection/injection"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// The elicitation gate (G0 M15 D33, D34; HR-420, HR-421). When a
// 2026-07-28 upstream server answers a tools/call with input_required, the
// 2026-07-28 face relays the requests to the agent unchanged, but only for
// a tool whose reviewed mapping declares elicitation fields, and only when
// every request is a form-mode elicitation whose requested schema asks for
// declared fields of compatible types, and whose text the injection scan
// finds clean. Anything else stays today's tool error, and a declared
// tool's refusal is reported as elicitation_refused. The first call stays
// recorded as it is today (FAILED, upstream_input_required).
//
// The server's requestState and request keys never reach the agent (D39,
// HR-075): the gateway keeps them as an ELICITATION state entry, bound to
// the call's connection, run and instance, and gives the agent a
// single-use random handle as its requestState. The agent's retry carrying
// inputResponses must present that handle for the same binding and tool;
// it is a new action: each accepted answer is checked against the asked
// and declared fields before anything is decided, becomes the material param elicitation.<field>, and goes
// upstream only when the Authority permits the action (dispatch builds the
// inputResponses from the permitted action). URL-mode elicitation,
// sampling and roots stay declined, and so does an elicitation/create on a
// 2025-11-25 stream (upstream.answer). The question's text is never kept:
// the gateway logs only its SHA-256 and the scan's result.

// Bounds on what the gate relays and accepts.
const (
	maxInputRequests = 16
	maxRequestState  = 4 << 10
)

var inputKeyRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// inputRequest is one request of an input_required result.
type inputRequest struct {
	Method string `json:"method"`
	Params struct {
		Mode            string         `json:"mode"`
		Message         string         `json:"message"`
		RequestedSchema *formSchema    `json:"requestedSchema"`
		URL             jsontext.Value `json:"url"`
	} `json:"params"`
}

// formSchema is an elicitation form's requested schema: a flat object.
type formSchema struct {
	Type       string                    `json:"type"`
	Properties map[string]jsontext.Value `json:"properties"`
	Required   []string                  `json:"required"`
}

// formField is one property of a form: a primitive.
type formField struct {
	Type        string         `json:"type"`
	Title       string         `json:"title,omitzero"`
	Description string         `json:"description,omitzero"`
	Enum        []string       `json:"enum,omitzero"`
	Default     jsontext.Value `json:"default,omitzero"`
	Minimum     jsontext.Value `json:"minimum,omitzero"`
	Maximum     jsontext.Value `json:"maximum,omitzero"`
	MinLength   int            `json:"minLength,omitzero"`
	MaxLength   int            `json:"maxLength,omitzero"`
}

// question is what the gateway keeps of one relayed or refused question.
type question struct {
	key, sha256, scan string
	sum               []byte
}

// Refusal reasons reported with elicitation_refused (D40); a refusal no
// reason fits is reported without one.
const (
	reasonURLMode         = "url_mode"
	reasonUndeclaredField = "undeclared_field"
	reasonTypeMismatch    = "type_mismatch"
	reasonDuplicateField  = "duplicate_field"
	reasonTooManyFields   = "too_many_fields"
	reasonInjection       = "injection_flagged"
)

// refusal says why the gate refuses: the reported reason ("" when none
// fits) and what the gateway logs.
type refusal struct {
	reason, why string
}

// screen checks an input_required result against the tool's declared
// elicitation fields (D33, D37, D39). It returns the requests and the
// request state to relay, the questions seen and, when it refuses, why;
// the refused question, if any, is the last one seen.
func screen(spec *domain.ElicitationSpec, body []byte) (requests jsontext.Value, stored storedElicitation, qs []question, no *refusal) {
	var res struct {
		InputRequests map[string]jsontext.Value `json:"inputRequests"`
		RequestState  jsontext.Value            `json:"requestState"`
	}
	if err := json.Unmarshal(body, &res); err != nil || len(res.InputRequests) == 0 {
		return nil, stored, nil, &refusal{why: "no input requests"}
	}
	if len(res.InputRequests) > maxInputRequests {
		return nil, stored, nil, &refusal{reasonTooManyFields, "too many input requests"}
	}
	if s := res.RequestState; len(s) > 0 && (s.Kind() != '"' || len(s) > maxRequestState) {
		return nil, stored, nil, &refusal{why: "a request state that is not a short string"}
	}
	asked := map[string]bool{}
	for _, key := range slices.Sorted(maps.Keys(res.InputRequests)) {
		var ir inputRequest
		if !inputKeyRe.MatchString(key) || json.Unmarshal(res.InputRequests[key], &ir) != nil {
			return nil, stored, qs, &refusal{why: "an input request that does not decode"}
		}
		sum := sha256.Sum256([]byte(ir.Params.Message))
		q := question{key: key, sha256: hex.EncodeToString(sum[:]), scan: injection.ScanClean, sum: sum[:]}
		no := checkRequest(spec, ir)
		if no == nil {
			// Field names are unique across the requests (D39).
			for name := range ir.Params.RequestedSchema.Properties {
				if asked[name] {
					no = &refusal{reasonDuplicateField, "a field asked for twice: " + name}
				}
				asked[name] = true
			}
		}
		if no == nil {
			texts := []string{ir.Params.Message}
			for _, raw := range ir.Params.RequestedSchema.Properties {
				var f formField
				_ = json.Unmarshal(raw, &f)
				texts = append(texts, f.Title, f.Description)
			}
			for _, t := range texts {
				if injection.Scan(t).Flagged {
					q.scan, no = injection.ScanFlagged, &refusal{reasonInjection, "the question reads like instructions"}
					break
				}
			}
		}
		qs = append(qs, q)
		if no != nil {
			return nil, stored, qs, no
		}
		schema, _ := json.Marshal(ir.Params.RequestedSchema, json.Deterministic(true))
		digest := sha256.Sum256(schema)
		stored.Requests = append(stored.Requests, storedRequest{
			Key: key, Fields: slices.Sorted(maps.Keys(ir.Params.RequestedSchema.Properties)), SchemaDigest: hex.EncodeToString(digest[:]),
		})
	}
	raw, err := json.Marshal(res.InputRequests, json.Deterministic(true))
	if err != nil {
		return nil, stored, qs, &refusal{why: "the input requests do not encode"}
	}
	if len(res.RequestState) > 0 && json.Unmarshal(res.RequestState, &stored.RequestState) != nil {
		return nil, stored, qs, &refusal{why: "a request state that is not a string"}
	}
	return raw, stored, qs, nil
}

// checkRequest checks one input request: a form-mode elicitation for
// declared fields of compatible types (D33, D37, HR-420); URL mode,
// sampling and roots stay declined (HR-421).
func checkRequest(spec *domain.ElicitationSpec, ir inputRequest) *refusal {
	switch {
	case ir.Method != "elicitation/create":
		return &refusal{why: ir.Method + " is not relayed"}
	case ir.Params.Mode != "" && ir.Params.Mode != "form":
		return &refusal{reasonURLMode, "a " + ir.Params.Mode + "-mode elicitation is not relayed"}
	case len(ir.Params.URL) > 0:
		return &refusal{reasonURLMode, "an elicitation with a URL is not relayed"}
	case ir.Params.Message == "" || len(ir.Params.Message) > maxRequestState:
		return &refusal{why: "an elicitation without a short message"}
	case ir.Params.RequestedSchema == nil || ir.Params.RequestedSchema.Type != "object" || len(ir.Params.RequestedSchema.Properties) == 0:
		return &refusal{reasonTypeMismatch, "an elicitation without a requested form"}
	case len(ir.Params.RequestedSchema.Properties) > domain.MaxElicitationFields:
		return &refusal{reasonTooManyFields, "a form with too many fields"}
	}
	s := ir.Params.RequestedSchema
	for _, name := range s.Required {
		if _, ok := s.Properties[name]; !ok {
			return &refusal{reasonTypeMismatch, "a required field the form does not ask for"}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(s.Properties)) {
		declared, ok := spec.Field(name)
		if !ok {
			return &refusal{reasonUndeclaredField, "a field the reviewed mapping does not declare: " + name}
		}
		var f formField
		if err := json.Unmarshal(s.Properties[name], &f, json.RejectUnknownMembers(true)); err != nil {
			return &refusal{reasonTypeMismatch, "a form field of an unsupported shape: " + name}
		}
		if !compatible(declared, f) {
			return &refusal{reasonTypeMismatch, "a form field of another type than declared: " + name}
		}
	}
	return nil
}

// compatible reports whether a form field asks for what a declared field
// holds: a string for an identifier or content, a string of declared enum
// values for an enum, a number for a decimal, an integer, a boolean.
func compatible(declared domain.ParamSpec, f formField) bool {
	switch declared.Type {
	case domain.TypeIdentifier, domain.TypeContent:
		return f.Type == "string" && len(f.Enum) == 0
	case domain.TypeEnum:
		return f.Type == "string" && len(f.Enum) > 0 && !slices.ContainsFunc(f.Enum, func(v string) bool { return !slices.Contains(declared.Values, v) })
	case domain.TypeDecimal:
		return f.Type == "number" && len(f.Enum) == 0
	case domain.TypeInteger:
		return f.Type == "integer" && len(f.Enum) == 0
	case domain.TypeBoolean:
		return f.Type == "boolean" && len(f.Enum) == 0
	case domain.TypeMoney, domain.TypeIdentifierList, domain.TypeText, domain.TypeCommand, domain.TypePath, domain.TypeQueryFilter:
		// Never an elicitation field (domain.ElicitationTypes).
	}
	return false
}

// relay answers a 2026-07-28 tools/call whose upstream server asked for
// input: the requests unchanged when the gate passes them, or false when
// the caller answers today's tool error. A declared tool's refusal is
// reported as elicitation_refused.
func (h *Handler) relay(ctx context.Context, conn *control.Connection, tool string, c called) (map[string]any, bool) {
	spec := conn.Mapper.Elicitation(tool)
	if spec == nil || c.res.Response == nil || c.res.Code != dispatch.CodeInputRequired {
		return nil, false
	}
	requests, stored, qs, no := screen(spec, c.res.Response.Body)
	attrs := []any{slog.String("connection_id", conn.GetId()), slog.String("transaction_id", c.res.TransactionID)}
	for _, q := range qs {
		attrs = append(attrs, slog.Group("question_"+q.key, slog.String("sha256", q.sha256), slog.String("scan", q.scan)))
	}
	if no != nil {
		h.log.WarnContext(ctx, "security.elicitation_refused", append(attrs, slog.String("reason", no.why))...)
		detail := dispatch.RefusalDetail{ElicitationReason: no.reason}
		if len(qs) > 0 {
			detail.QuestionSHA256 = qs[len(qs)-1].sum
		}
		h.engine.ReportElicitationRefused(ctx, conn, c.action.Action, detail)
		return nil, false
	}
	// The server's request state and request keys stay with the gateway
	// (D39, HR-075): the agent gets a single-use handle in their place.
	stored.Tool = tool
	handle, err := h.keepElicitation(c.b, stored)
	if err != nil {
		h.log.WarnContext(ctx, "gateway.elicitation_not_kept", append(attrs, pclog.Err(err))...)
		return nil, false
	}
	h.log.InfoContext(ctx, "gateway.elicitation_relayed", attrs...)
	return map[string]any{
		"resultType": "input_required", "inputRequests": requests, "requestState": handle,
		"_meta": map[string]any{metaResult: map[string]any{
			"transaction_id": c.res.TransactionID, "outcome": outcome(c.res), "decision": decision(c.res), "mode": mode(c.res),
			"receipt": c.res.Receipt,
		}},
	}, true
}

// elicitationTTL is how long a relayed elicitation can be answered (D39).
const elicitationTTL = 10 * time.Minute

// storedElicitation is what the gateway keeps of a relayed elicitation
// (D39): the tool, the server's request state and, of each request, its
// key, the fields it asked for and its schema's digest. Never the question.
type storedElicitation struct {
	Tool         string          `json:"tool"`
	RequestState string          `json:"request_state,omitzero"`
	Requests     []storedRequest `json:"requests"`
}

type storedRequest struct {
	Key          string   `json:"key"`
	Fields       []string `json:"fields"`
	SchemaDigest string   `json:"schema_digest"`
}

// keepElicitation stores a relayed elicitation under the SHA-256 of a
// fresh random handle, for b, and returns the handle (base64url).
func (h *Handler) keepElicitation(b binding, s storedElicitation) (string, error) {
	var handle [32]byte
	if _, err := rand.Read(handle[:]); err != nil {
		return "", err
	}
	body, err := json.Marshal(s, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	if _, err := h.holds.putElicitation(sha256.Sum256(handle[:]), b, body, h.holds.now().Add(elicitationTTL), 0); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(handle[:]), nil
}

// claimElicitation resolves a retry's handle (D39): a live elicitation of
// this binding and tool, deleted so the handle is single use. A handle
// that does not resolve, or a lost race, is errAnswer.
func (h *Handler) claimElicitation(b binding, tool string, raw jsontext.Value) (storedElicitation, error) {
	var s storedElicitation
	var text string
	if raw.Kind() != '"' || json.Unmarshal(raw, &text) != nil {
		return s, fmt.Errorf("%w: no requestState handle", errAnswer)
	}
	handle, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil || len(handle) != 32 {
		return s, fmt.Errorf("%w: requestState is not a handle", errAnswer)
	}
	k := key(sha256.Sum256(handle))
	e, found, err := h.holds.getElicitation(k)
	if err != nil || !found || e.binding != b || json.Unmarshal(e.body, &s) != nil || s.Tool != tool {
		return storedElicitation{}, fmt.Errorf("%w: the handle answers no elicitation of this call", errAnswer)
	}
	if deleted, err := h.holds.deleteElicitation(k, e.version); err != nil || !deleted {
		return storedElicitation{}, fmt.Errorf("%w: the handle was used", errAnswer)
	}
	return s, nil
}

// errAnswer reports inputResponses the reviewed mapping does not allow.
var errAnswer = errors.New("the input responses do not answer the reviewed elicitation fields")

// answers reads a retry's inputResponses (D33, D39): each key one the stored
// elicitation asked, its action and, for an accepted one, its content,
// every field one that request asked for and the mapping declares, of its
// declared type and answered once. It returns the answers as typed values
// and what the dispatch needs to answer the server, with the stored
// request state.
func answers(spec *domain.ElicitationSpec, raw jsontext.Value, stored storedElicitation) (domain.Values, dispatch.InputResponses, error) {
	ir := dispatch.InputResponses{Keys: map[string]dispatch.InputResponse{}}
	if spec == nil {
		return nil, ir, fmt.Errorf("%w: the tool declares no elicitation", errAnswer)
	}
	var responses map[string]jsontext.Value
	if raw.Kind() != '{' || json.Unmarshal(raw, &responses) != nil || len(responses) == 0 || len(responses) > maxInputRequests {
		return nil, ir, errAnswer
	}
	ir.RequestState = stored.RequestState
	vals := domain.Values{}
	for _, key := range slices.Sorted(maps.Keys(responses)) {
		var r struct {
			Action  string                    `json:"action"`
			Content map[string]jsontext.Value `json:"content"`
		}
		if !inputKeyRe.MatchString(key) || json.Unmarshal(responses[key], &r, json.RejectUnknownMembers(true)) != nil {
			return nil, ir, errAnswer
		}
		i := slices.IndexFunc(stored.Requests, func(q storedRequest) bool { return q.Key == key })
		if i < 0 {
			return nil, ir, fmt.Errorf("%w: %s was not asked", errAnswer, key)
		}
		resp := dispatch.InputResponse{Action: r.Action}
		switch {
		case r.Action == "accept" && len(r.Content) > 0:
		case (r.Action == "decline" || r.Action == "cancel") && r.Content == nil:
		default:
			return nil, ir, fmt.Errorf("%w: %s", errAnswer, key)
		}
		for _, name := range slices.Sorted(maps.Keys(r.Content)) {
			f, ok := spec.Field(name)
			if _, twice := vals[name]; !ok || twice || !slices.Contains(stored.Requests[i].Fields, name) {
				return nil, ir, fmt.Errorf("%w: field %s", errAnswer, name)
			}
			v, err := answerValue(f.Type, r.Content[name])
			if err != nil {
				return nil, ir, fmt.Errorf("%w: field %s", errAnswer, name)
			}
			vals[name] = v
			resp.Fields = append(resp.Fields, name)
		}
		ir.Keys[key] = resp
	}
	return vals, ir, nil
}

// answerValue reads one answer as its declared type; the declared spec's
// limits are checked when the action is mapped.
func answerValue(t domain.ParamType, raw jsontext.Value) (domain.Value, error) {
	v := domain.Value{Type: t}
	var err error
	switch t {
	case domain.TypeIdentifier, domain.TypeContent, domain.TypeEnum:
		if raw.Kind() != '"' {
			return v, errAnswer
		}
		err = json.Unmarshal(raw, &v.Str)
	case domain.TypeBoolean:
		err = json.Unmarshal(raw, &v.Bool)
	case domain.TypeInteger:
		if raw.Kind() != '0' {
			return v, errAnswer
		}
		err = json.Unmarshal(raw, &v.Int)
	case domain.TypeDecimal:
		if raw.Kind() != '0' {
			return v, errAnswer
		}
		v.Decimal, err = money.Parse(string(raw))
	case domain.TypeMoney, domain.TypeIdentifierList, domain.TypeText, domain.TypeCommand, domain.TypePath, domain.TypeQueryFilter:
		return v, errAnswer
	}
	if err != nil {
		return v, fmt.Errorf("%w: %w", actionir.ErrAmbiguous, err)
	}
	return v, nil
}
