// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/katocxl/pantherclaw/internal/gateway"
	idapp "github.com/katocxl/pantherclaw/internal/idaccess/app"
	iddomain "github.com/katocxl/pantherclaw/internal/idaccess/domain"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/sim/okta"
)

// idpRanges holds each driver's IdP-native access set-up: it is made on a
// scenario's first idp.probe step.
var idpRanges sync.Map // *rangeDriver -> *idpAccess

func (d *rangeDriver) idpRange() *idpAccess {
	if a, ok := idpRanges.Load(d); ok {
		return a.(*idpAccess)
	}
	a := d.s.idpAccessOn(d.t)
	idpRanges.Store(d, a)
	d.t.Cleanup(func() { idpRanges.Delete(d) })
	return a
}

var (
	papCodeRE   = regexp.MustCompile(`PAP/1: ([a-z_]+)`)
	challengeRE = regexp.MustCompile(`error="([a-z_]+)"`)
)

// idpRefused is the observation of a token endpoint refusal: NO_GRANT, or
// the OAuth error in upper case.
func idpRefused(err error) domain.Observation {
	code, desc := oauthErr(err)
	reason := strings.ToUpper(code)
	if strings.Contains(desc, idapp.ReasonNoGrant) {
		reason = idapp.ReasonNoGrant
	}
	return domain.Observation{Outcome: domain.OutcomeRefused, Reason: reason, Code: code, Detail: desc}
}

// idpCall is the observation of a call through the gateway: ALLOW when the
// tool ran, otherwise REFUSED with the PAP/1 code or the challenge's error,
// or DENY with the decision's reasons.
func idpCall(status int, challenge, body string) domain.Observation {
	if succeeded(status, body) {
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "the tool ran"}
	}
	obs := domain.Observation{Outcome: domain.OutcomeRefused, Code: fmt.Sprint(status), Detail: firstN([]byte(body), 600)}
	if m := papCodeRE.FindStringSubmatch(body); m != nil {
		obs.Reason = strings.ToUpper(m[1])
	} else if m := challengeRE.FindStringSubmatch(challenge); m != nil {
		obs.Reason = strings.ToUpper(m[1])
	}
	var r struct {
		Result struct {
			Meta map[string]struct {
				Reasons []string `json:"reasons"`
			} `json:"_meta"`
		} `json:"result"`
	}
	if json.Unmarshal([]byte(body), &r) == nil {
		for _, f := range r.Result.Meta {
			if len(f.Reasons) > 0 {
				obs.Outcome, obs.Reasons, obs.Reason = domain.OutcomeDeny, f.Reasons, f.Reasons[0]
			}
		}
	}
	return obs
}

// idpProbe runs idp.probe (G0 M26 D400-D403, D408; RT-150..RT-153).
func (d *rangeDriver) idpProbe(st domain.Step) (domain.Observation, error) {
	var w struct {
		Attack string `json:"attack"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	t, a := d.t, d.idpRange()
	ctx := context.Background()
	viaBearer := func(token string) domain.Observation {
		status, challenge, body := a.call(t, iddomain.ResourcePath+idpConnection, idpRefund("9.00"), map[string]string{"Authorization": "Bearer " + token})
		return idpCall(status, challenge, body)
	}
	exchanged := func(assertion string) (string, string, *domain.Observation) {
		res, err := a.exchange(t, assertion)
		if err != nil {
			obs := idpRefused(err)
			return "", "", &obs
		}
		return res.AccessToken, res.RunID, nil
	}
	faulty := func(f okta.Faults) string {
		a.sim.SetFaults(f)
		defer a.sim.SetFaults(okta.Faults{})
		return a.assert(t, idpPerson, idpClientID)
	}

	switch w.Attack {
	case "granted":
		tok, _, refused := exchanged(a.assert(t, idpPerson, idpClientID))
		if refused != nil {
			return *refused, nil
		}
		return viaBearer(tok), nil
	case "no_grant":
		if _, _, refused := exchanged(a.assert(t, idpNobody, idpClientID)); refused != nil {
			return *refused, nil
		}
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "a person with no grant got a token"}, nil
	case "replayed_assertion":
		j := a.assert(t, idpPerson, idpClientID)
		if _, _, refused := exchanged(j); refused != nil {
			return domain.Observation{}, fmt.Errorf("the first use was refused: %+v", *refused)
		}
		if _, _, refused := exchanged(j); refused != nil {
			return *refused, nil
		}
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "an assertion was used twice"}, nil
	case "expired_assertion", "wrong_audience":
		f := okta.Faults{Expired: w.Attack == "expired_assertion", WrongAudience: w.Attack == "wrong_audience"}
		if _, _, refused := exchanged(faulty(f)); refused != nil {
			return *refused, nil
		}
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: w.Attack + " was accepted"}, nil

	case "mcp_token_on_pap_route":
		tok, run, refused := exchanged(a.assert(t, idpPerson, idpClientID))
		if refused != nil {
			return domain.Observation{}, fmt.Errorf("exchange: %+v", *refused)
		}
		status, challenge, body := a.call(t, "/mcp/"+idpConnection, idpRefund("9.00"), map[string]string{
			"Authorization": "PAP " + tok, gateway.HeaderRunID: run, gateway.HeaderProof: "a-proof-from-no-key",
		})
		return idpCall(status, challenge, body), nil
	case "workload_token_on_oauth_route":
		return viaBearer(d.s.token), nil
	case "token_for_other_server":
		tok, _, refused := exchanged(a.assert(t, idpPerson, idpClientID, iddomain.ResourceURL(d.s.gateway, "github")))
		if refused != nil {
			return *refused, nil
		}
		return viaBearer(tok), nil
	case "proof_on_oauth_route":
		tok, _, refused := exchanged(a.assert(t, idpPerson, idpClientID))
		if refused != nil {
			return domain.Observation{}, fmt.Errorf("exchange: %+v", *refused)
		}
		status, challenge, body := a.call(t, iddomain.ResourcePath+idpConnection, idpRefund("9.00"), map[string]string{
			"Authorization": "Bearer " + tok, gateway.HeaderProof: "a-proof",
		})
		return idpCall(status, challenge, body), nil

	case "unbound_client":
		const unbound = "0oa-not-bound"
		key, kid := strangerKey(t)
		if _, err := a.exchangeAs(t, a.assert(t, idpPerson, unbound), unbound, key, kid); err != nil {
			return idpRefused(err), nil
		}
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "an unbound client got a token"}, nil
	case "key_of_no_instance":
		key, kid := strangerKey(t)
		if _, err := a.exchangeAs(t, a.assert(t, idpPerson, idpClientID), idpClientID, key, kid); err != nil {
			return idpRefused(err), nil
		}
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "a key no instance holds authenticated the client"}, nil
	case "removed_binding":
		tok, _, refused := exchanged(a.assert(t, idpPerson, idpClientID))
		if refused != nil {
			return domain.Observation{}, fmt.Errorf("exchange: %+v", *refused)
		}
		d.s.exec(t, "UPDATE pc.org_assertion_clients SET state = 'REMOVED', removed_by = $2, removed_at = now() WHERE id = $1", a.binding, a.person)
		return viaBearer(tok), nil

	case "code_flow":
		res, err := a.redeem(a.approve(t), idpVerifier, idpRedirect)
		if err != nil {
			return idpRefused(err), nil
		}
		return viaBearer(res.AccessToken), nil
	case "code_replay":
		code := a.approve(t)
		if _, err := a.redeem(code, idpVerifier, idpRedirect); err != nil {
			return domain.Observation{}, fmt.Errorf("the first redemption: %w", err)
		}
		if _, err := a.redeem(code, idpVerifier, idpRedirect); err != nil {
			return idpRefused(err), nil
		}
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "a code was redeemed twice"}, nil
	case "wrong_verifier":
		if _, err := a.redeem(a.approve(t), idpVerifier+"-stolen", idpRedirect); err != nil {
			return idpRefused(err), nil
		}
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "a code was redeemed without its verifier"}, nil
	case "unregistered_redirect":
		q := a.authorizeQuery()
		q.Set("redirect_uri", "http://127.0.0.1:9/attacker")
		_, err := a.flow.Approve(ctx, d.s.org, a.person, q)
		var ae *idapp.AuthorizeError
		if errors.As(err, &ae) {
			return domain.Observation{Outcome: domain.OutcomeRefused, Reason: strings.ToUpper(ae.Code), Detail: ae.Description}, nil
		} else if err != nil {
			return domain.Observation{}, err
		}
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "a code was sent to an unregistered redirect"}, nil
	case "refresh_reuse":
		first, err := a.redeem(a.approve(t), idpVerifier, idpRedirect)
		if err != nil {
			return domain.Observation{}, fmt.Errorf("redeem: %w", err)
		}
		second, err := a.refresh(first.RefreshToken)
		if err != nil {
			return domain.Observation{}, fmt.Errorf("the first refresh: %w", err)
		}
		_, reuse := a.refresh(first.RefreshToken)
		if reuse == nil {
			return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "a rotated refresh token was used again"}, nil
		}
		if _, err := a.refresh(second.RefreshToken); err == nil {
			return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "the family survived a reuse"}, nil
		}
		return idpRefused(reuse), nil
	}
	if w.Attack == "" {
		return domain.Observation{}, errors.New("idp.probe needs an attack")
	}
	return domain.Observation{Code: fmt.Sprint(http.StatusNotImplemented)}, fmt.Errorf("unknown idp.probe attack %q", w.Attack)
}
