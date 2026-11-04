// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// KindModel is a model provider's API reached through the gateway (G0 M29
// D811, HR-690): backed only by pc.anthropic or pc.openai (and, since G0 M31
// D961, pc.vertex or pc.bedrock), held by
// PantherClaw only, its limits fixed (D814) rather than the connection's.
const KindModel = "model"

// Model connection defaults and limits (D811).
const (
	DefaultModelMaxOutputTokens = 64_000
	MaxModelMaxOutputTokens     = 1_000_000
	maxModelServerTools         = 32
)

// ModelPackageCredential is where a model package's key goes by default
// (D811): an admin may name another header (Azure's api-key).
type ModelPackageCredential struct {
	Header, Scheme string
	// TokenHost: the credential mints its token at another host (a Google
	// token endpoint, AWS STS), which the connection's allowed hosts must
	// name beside the base URL's (G0 M31 D961).
	TokenHost bool
}

// ModelPackages are the packages that back model connections, and back
// nothing else (D811). pc.vertex holds a google_service_account and
// pc.bedrock an aws_sigv4 credential (G0 M31 D961).
var ModelPackages = map[string]ModelPackageCredential{
	"pc.anthropic": {Header: "x-api-key"},
	"pc.openai":    {Header: "Authorization", Scheme: "Bearer"},
	"pc.vertex":    {Header: "Authorization", Scheme: "Bearer", TokenHost: true},
	"pc.bedrock":   {Header: "Authorization", Scheme: "AWS4-HMAC-SHA256", TokenHost: true},
}

// Errors of the model kind.
var (
	ErrModelConfig = pcerr.New(pcerr.InvalidArgument, "MODEL_CONFIG_INVALID",
		"a model connection needs max output tokens 1..1,000,000, at most 32 distinct lowercase server tool types, "+
			"and a price, when set, of a known currency with decimal input and output prices (cache prices optional)")
	// ErrModelPriceEdition: prices and estimates need Team (D829, HR-698).
	ErrModelPriceEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"prices on model connections need the Team edition")
)

var serverToolRE = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

// ModelConfig is a model connection's settings (D811, D813, D829).
type ModelConfig struct {
	// MaxOutputTokens is added to a request that has none; 0 takes the
	// default.
	MaxOutputTokens int64 `json:"max_output_tokens"`
	// AllowedServerTools are the provider-side tool types an admin allowed
	// (HR-696).
	AllowedServerTools []string `json:"allowed_server_tools"`
	// Price is for estimates only (Team); nil = no price.
	Price *ModelPrice `json:"price,omitzero"`
	// CapturePrompts keeps the connection's requests and replies as a
	// capture profile that covers it asks (Business, G0 M30 D945b). Turning
	// it on waits for a second person's security key; off applies at once.
	CapturePrompts bool `json:"capture_prompts,omitzero"`
}

// ModelPrice is a price per million tokens, as decimal strings; empty cache
// prices mean the input price.
type ModelPrice struct {
	Currency   string `json:"currency"`
	Input      string `json:"input"`
	Output     string `json:"output"`
	CacheRead  string `json:"cache_read,omitzero"`
	CacheWrite string `json:"cache_write,omitzero"`
}

// Check returns the configuration with its defaults, tools sorted.
func (m ModelConfig) Check() (ModelConfig, error) {
	out := ModelConfig{MaxOutputTokens: orDefault(m.MaxOutputTokens, DefaultModelMaxOutputTokens), CapturePrompts: m.CapturePrompts}
	if out.MaxOutputTokens < 1 || out.MaxOutputTokens > MaxModelMaxOutputTokens || len(m.AllowedServerTools) > maxModelServerTools {
		return ModelConfig{}, ErrModelConfig
	}
	out.AllowedServerTools = []string{}
	for _, t := range m.AllowedServerTools {
		if !serverToolRE.MatchString(t) || slices.Contains(out.AllowedServerTools, t) {
			return ModelConfig{}, ErrModelConfig
		}
		out.AllowedServerTools = append(out.AllowedServerTools, t)
	}
	slices.Sort(out.AllowedServerTools)
	if p := m.Price; p != nil {
		if _, err := money.ParseCurrency(p.Currency); err != nil {
			return ModelConfig{}, ErrModelConfig
		}
		for i, v := range []string{p.Input, p.Output, p.CacheRead, p.CacheWrite} {
			if v == "" && i >= 2 {
				continue
			}
			if d, err := money.Parse(v); err != nil || d.Sign() < 0 || strings.HasPrefix(v, "-") {
				return ModelConfig{}, ErrModelConfig
			}
		}
		cp := *p
		out.Price = &cp
	}
	return out, nil
}

// checkModelPrice refuses a price unless the edition is Team or above (D829);
// without an edition source it refuses (fail closed).
func (s *Service) checkModelPrice(ctx context.Context, m *ModelConfig) error {
	if m == nil || m.Price == nil {
		return nil
	}
	if s.ents == nil {
		return ErrModelPriceEdition
	}
	e, err := s.ents.Current(ctx)
	if err != nil {
		return err
	}
	if !e.TokenCostReports() {
		return ErrModelPriceEdition
	}
	return nil
}

// checkModelCreate checks what a model connection's creation needs before
// the defaults apply (D811): one of the model packages, held access, and
// no timeout or answer cap of its own (the model path's are fixed, D814).
// The credential header defaults to the package's. Another kind never uses
// a model package.
func checkModelCreate(in *CreateInput) error {
	cred, model := ModelPackages[in.Package]
	switch {
	case model != (in.Kind == KindModel):
		return ErrShape
	case in.Kind != KindModel:
		if in.Model != nil {
			return ErrShape
		}
		return nil
	case in.AccessMode != AccessHeld || in.TimeoutMs != 0 || in.MaxResponseBytes != 0 || in.ModelRelay:
		return ErrShape
	}
	if in.CredentialHeader == "" {
		in.CredentialHeader, in.CredentialScheme = cred.Header, cred.Scheme
	}
	if in.Model == nil {
		in.Model = &ModelConfig{}
	}
	return nil
}

// modelShape is a model connection's base URL and hosts (D811): an https
// base URL with an optional path prefix (a loopback or private literal over
// http when simulated), and the credential sent to its host only.
func (s *Service) modelShape(pkg, baseURL string, allowed []string, simulated bool, scheme, header string) (*string, []string, error) {
	if header == "" || (scheme != "" && header == "") {
		return nil, nil, ErrShape
	}
	norm, ep, err := checkBaseURL(baseURL, s.own)
	if err != nil {
		return nil, nil, err
	}
	if u, _ := url.Parse(norm); u == nil || (u.Scheme != "https" && !simulated) {
		return nil, nil, ErrPlainHTTP
	}
	hosts, err := checkAllowedHosts(nil, ep, norm, s.own)
	if err != nil {
		return nil, nil, err
	}
	if len(allowed) > 0 && !slices.Equal(allowed, hosts) {
		// A package whose credential mints at another host names it too,
		// beside the base URL's host (G0 M31 D961).
		if !ModelPackages[pkg].TokenHost {
			return nil, nil, ErrShape
		}
		all, err := checkAllowedHosts(allowed, ep, norm, s.own)
		if err != nil {
			return nil, nil, err
		}
		if !slices.Contains(all, hosts[0]) {
			return nil, nil, ErrShape
		}
		hosts = all
	}
	if simulated {
		if err := checkSimulated(&norm, hosts); err != nil {
			return nil, nil, err
		}
	}
	return &norm, hosts, nil
}

// loadModel reads a model connection's settings; nil for another kind.
func loadModel(ctx context.Context, q *dbq.Queries, conn dbq.PcConnection) (*ModelConfig, error) {
	if conn.Kind != KindModel {
		return nil, nil
	}
	row, err := q.GetModelConnection(ctx, conn.OrgID, conn.ID)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return ModelConfigFromRow(row), nil
}

// ModelConfigFromRow is a stored model configuration.
func ModelConfigFromRow(row dbq.GetModelConnectionRow) *ModelConfig {
	out := &ModelConfig{MaxOutputTokens: row.MaxOutputTokens, AllowedServerTools: row.AllowedServerTools, CapturePrompts: row.CapturePrompts}
	if row.PriceCurrency != nil && row.PriceInput != nil && row.PriceOutput != nil {
		str := func(d *money.Decimal) string {
			if d == nil {
				return ""
			}
			return d.String()
		}
		out.Price = &ModelPrice{
			Currency: *row.PriceCurrency, Input: str(row.PriceInput), Output: str(row.PriceOutput),
			CacheRead: str(row.PriceCacheRead), CacheWrite: str(row.PriceCacheWrite),
		}
	}
	return out
}

// SaveModel writes a checked model configuration (the model kind store's
// Save, G0 M29 D811).
func SaveModel(ctx context.Context, tx db.TenantTx, org ids.OrgID, conn ids.UUID, m *ModelConfig) error {
	p := dbq.PutModelConnectionParams{
		OrgID: org, ConnectionID: conn, MaxOutputTokens: m.MaxOutputTokens, AllowedServerTools: m.AllowedServerTools,
		CapturePrompts: m.CapturePrompts,
	}
	if p.AllowedServerTools == nil {
		p.AllowedServerTools = []string{}
	}
	if pr := m.Price; pr != nil {
		dec := func(v string) (*money.Decimal, error) {
			if v == "" {
				return nil, nil
			}
			d, err := money.Parse(v)
			if err != nil {
				return nil, ErrModelConfig
			}
			return &d, nil
		}
		var err error
		cur := pr.Currency
		p.PriceCurrency = &cur
		if p.PriceInput, err = dec(pr.Input); err != nil {
			return err
		}
		if p.PriceOutput, err = dec(pr.Output); err != nil {
			return err
		}
		if p.PriceCacheRead, err = dec(pr.CacheRead); err != nil {
			return err
		}
		if p.PriceCacheWrite, err = dec(pr.CacheWrite); err != nil {
			return err
		}
	}
	return dbq.New(tx).PutModelConnection(ctx, p)
}

// modelWeakens reports whether a new model configuration widens what the
// connection lets through (HR-183): a higher max output tokens or a newly
// allowed server tool, or prompt capture turned on (G0 M30 D945b). A price change alone is neither.
func modelWeakens(before, after *ModelConfig) bool {
	if before == nil {
		return true
	}
	if captureTurnsOn(before, after) {
		return true
	}
	if after.MaxOutputTokens > before.MaxOutputTokens {
		return true
	}
	for _, t := range after.AllowedServerTools {
		if !slices.Contains(before.AllowedServerTools, t) {
			return true
		}
	}
	return false
}

// modelSummary is a model configuration in an audit record: never a price
// in a weakening notice, only that one is set.
func modelSummary(m *ModelConfig) string {
	if m == nil {
		return ""
	}
	s := "max_output_tokens=" + strconv.FormatInt(m.MaxOutputTokens, 10) + " server_tools=" + strings.Join(m.AllowedServerTools, "|")
	if m.Price != nil {
		s += " price=" + m.Price.Currency
	}
	if m.CapturePrompts {
		s += " capture_prompts=on"
	}
	return s
}
