// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package bundlerpc serves BundleService over Connect (G0 M37 D1081–D1083;
// HR-795..800).
package bundlerpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	bundlesapp "github.com/katocxl/pantherclaw/internal/bundles/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler serves BundleService.
type Handler struct {
	pantherclawv1connect.UnimplementedBundleServiceHandler
	svc *bundlesapp.Service
}

// New returns the BundleService handler.
func New(svc *bundlesapp.Service) *Handler { return &Handler{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

func strs(in []ids.UUID) []string {
	out := make([]string, 0, len(in))
	for _, id := range in {
		out = append(out, id.String())
	}
	return out
}

// PinPublisherKey implements BundleServiceHandler.
func (h *Handler) PinPublisherKey(ctx context.Context, req *pantherclawv1.PinPublisherKeyRequest) (
	*pantherclawv1.PinPublisherKeyResponse, error,
) {
	p, err := h.svc.PinKey(ctx, bundlesapp.NewPin{
		Publisher: req.GetPublisher(), PublicKey: req.GetPublicKey(), AllowedKinds: req.GetAllowedKinds(),
		RevocationsURL: req.GetRevocationsUrl(), ExpectedFingerprint: req.GetExpectedFingerprint(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.PinPublisherKeyResponse{Pin: h.pin(p)}, nil
}

// ListPublisherPins implements BundleServiceHandler.
func (h *Handler) ListPublisherPins(ctx context.Context, req *pantherclawv1.ListPublisherPinsRequest) (
	*pantherclawv1.ListPublisherPinsResponse, error,
) {
	rows, next, err := h.svc.ListPins(ctx, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPublisherPinsResponse{NextPageToken: next}
	for _, p := range rows {
		out.Pins = append(out.Pins, h.pin(p))
	}
	return out, nil
}

// GetPublisherPin implements BundleServiceHandler.
func (h *Handler) GetPublisherPin(ctx context.Context, req *pantherclawv1.GetPublisherPinRequest) (
	*pantherclawv1.GetPublisherPinResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	p, err := h.svc.GetPin(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetPublisherPinResponse{Pin: h.pin(p)}, nil
}

// ActivatePublisherPin implements BundleServiceHandler: over the API it is
// always refused (STEP_UP_REQUIRED); a person activates a pin on its page
// with a security key (HR-795).
func (h *Handler) ActivatePublisherPin(ctx context.Context, req *pantherclawv1.ActivatePublisherPinRequest) (
	*pantherclawv1.ActivatePublisherPinResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	p, err := h.svc.ActivatePin(ctx, id, nil)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ActivatePublisherPinResponse{Pin: h.pin(p)}, nil
}

// RevokePublisherPin implements BundleServiceHandler.
func (h *Handler) RevokePublisherPin(ctx context.Context, req *pantherclawv1.RevokePublisherPinRequest) (
	*pantherclawv1.RevokePublisherPinResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	p, revoked, err := h.svc.RevokePin(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokePublisherPinResponse{Pin: h.pin(p), RevokedInstalls: strs(revoked)}, nil
}

// InstallBundle implements BundleServiceHandler.
func (h *Handler) InstallBundle(ctx context.Context, req *pantherclawv1.InstallBundleRequest) (
	*pantherclawv1.InstallBundleResponse, error,
) {
	in, err := h.svc.InstallBundle(ctx, req.GetBundle())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.InstallBundleResponse{Install: install(in)}, nil
}

// ListBundleInstalls implements BundleServiceHandler.
func (h *Handler) ListBundleInstalls(ctx context.Context, req *pantherclawv1.ListBundleInstallsRequest) (
	*pantherclawv1.ListBundleInstallsResponse, error,
) {
	rows, next, err := h.svc.ListInstalls(ctx, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListBundleInstallsResponse{NextPageToken: next}
	for _, in := range rows {
		out.Installs = append(out.Installs, install(in))
	}
	return out, nil
}

// GetBundleInstall implements BundleServiceHandler.
func (h *Handler) GetBundleInstall(ctx context.Context, req *pantherclawv1.GetBundleInstallRequest) (
	*pantherclawv1.GetBundleInstallResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	in, err := h.svc.GetInstall(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetBundleInstallResponse{Install: install(in)}, nil
}

// RevokeBundleInstall implements BundleServiceHandler.
func (h *Handler) RevokeBundleInstall(ctx context.Context, req *pantherclawv1.RevokeBundleInstallRequest) (
	*pantherclawv1.RevokeBundleInstallResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	revoked, err := h.svc.RevokeInstall(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeBundleInstallResponse{RevokedInstalls: strs(revoked)}, nil
}

// SubmitRevocation implements BundleServiceHandler.
func (h *Handler) SubmitRevocation(ctx context.Context, req *pantherclawv1.SubmitRevocationRequest) (
	*pantherclawv1.SubmitRevocationResponse, error,
) {
	a, err := h.svc.SubmitRevocation(ctx, req.GetStatement())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SubmitRevocationResponse{
		RevokedInstalls: strs(a.Installs), RevokedPins: strs(a.Pins), AlreadyApplied: a.AlreadyApplied,
	}, nil
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func (h *Handler) pin(p bundlesapp.Pin) *pantherclawv1.PublisherPin {
	out := &pantherclawv1.PublisherPin{
		Id: p.ID.String(), Publisher: p.Publisher, Kid: p.KID, Fingerprint: p.Fingerprint, AllowedKinds: p.AllowedKinds,
		RevocationsUrl: p.RevocationsURL, State: p.State, RevokeReason: p.RevokeReason, CreatedBy: p.CreatedBy,
		CreateTime: timestamppb.New(p.CreatedAt), ActivateTime: ts(p.ActivatedAt), RevokeTime: ts(p.RevokedAt),
		ConfirmUrl: h.svc.ConfirmURL(p.ID),
	}
	if p.ActivatedBy != nil {
		out.ActivatedBy = p.ActivatedBy.String()
	}
	return out
}

func install(in bundlesapp.Install) *pantherclawv1.BundleInstall {
	out := &pantherclawv1.BundleInstall{
		Id: in.ID.String(), Publisher: in.Publisher, Name: in.Name, Version: in.Version, BundleSha256: in.BundleSHA256,
		State: in.State, InstalledBy: in.InstalledBy.String(), CreateTime: timestamppb.New(in.CreatedAt),
		FinishTime: ts(in.FinishedAt), FailureCode: in.FailureCode,
	}
	if in.PinID != nil {
		out.PinId = in.PinID.String()
	}
	for _, it := range in.Items {
		out.Items = append(out.Items, &pantherclawv1.BundleItem{
			Kind: it.Kind, Name: it.Name, Sha256: it.SHA256, TargetType: it.TargetType, TargetId: it.TargetID, State: it.State,
		})
	}
	return out
}
