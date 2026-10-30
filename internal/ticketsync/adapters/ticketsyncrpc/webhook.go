// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ticketsyncrpc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tsapp "github.com/katocxl/pantherclaw/internal/ticketsync/app"
	"github.com/katocxl/pantherclaw/internal/ticketsync/domain"
)

// orgOf is the caller's organization.
func orgOf(ctx context.Context) (ids.OrgID, error) {
	c, err := tenancy.CallerFrom(ctx)
	return c.Org, err
}

// Webhooks receives inbound ticket webhooks (D255): POST
// /webhooks/tickets/<org>/<config>. It is public; the configuration's
// signature is the credential, checked before the body is read further.
// Every refusal looks the same to the sender but a bad signature.
type Webhooks struct {
	Svc *tsapp.Service
}

// Mount adds the route to mux.
func (w Webhooks) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST "+WebhookPath+"{org}/{config}", w.serve)
}

func (w Webhooks) serve(rw http.ResponseWriter, r *http.Request) {
	org, err := ids.Parse[ids.Org](r.PathValue("org"))
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	config, err := ids.ParseUUID(r.PathValue("config"))
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		http.Error(rw, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, domain.MaxWebhookBytes))
	if err != nil {
		http.Error(rw, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	_, err = w.Svc.Inbound(r.Context(), org, config, r.Header.Get(domain.JiraDeliveryHeader), r.Header.Get(domain.JiraSignatureHeader), body)
	switch {
	case err == nil:
		rw.WriteHeader(http.StatusNoContent)
	case errors.Is(err, tsapp.ErrSignature):
		http.Error(rw, "signature does not verify", http.StatusUnauthorized)
	case errors.Is(err, tsapp.ErrWebhook):
		http.Error(rw, "not an issue or comment event", http.StatusBadRequest)
	case errors.Is(err, tsapp.ErrNotFound), errors.Is(err, tsapp.ErrEdition):
		http.NotFound(rw, r)
	default:
		http.Error(rw, "try again", http.StatusServiceUnavailable)
	}
}
