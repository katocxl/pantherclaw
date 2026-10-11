// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// WithHub serves WatchContainment from hub.
func (h *GatewayHandler) WithHub(hub *gwapp.Hub) *GatewayHandler {
	h.hub = hub
	return h
}

func containmentOf(kind pantherclawv1.ContainmentStateKind, c gwapp.Containment) *pantherclawv1.WatchContainmentResponse {
	out := &pantherclawv1.WatchContainmentResponse{
		Kind: kind, Epoch: c.Epoch, KillSwitch: c.KillSwitch, ConfigVersion: c.ConfigVersion, GatewayActive: c.GatewayActive,
		AsOf: timestamppb.New(c.AsOf), VerificationsWaiting: c.VerificationsWaiting,
	}
	if kind != pantherclawv1.ContainmentStateKind_CONTAINMENT_STATE_KIND_HEARTBEAT {
		for id, st := range c.Connections {
			out.Connections = append(out.Connections, &pantherclawv1.ConnectionStateEntry{ConnectionId: id.String(), State: st})
		}
		sort.Slice(out.Connections, func(i, j int) bool { return out.Connections[i].ConnectionId < out.Connections[j].ConnectionId })
	}
	return out
}

// WatchContainment implements GatewayServiceHandler (HR-010): a snapshot
// first, then the state again whenever it changes and a heartbeat every
// HeartbeatEvery, but only while the server confirmed the state from the
// database within ConfirmedWithin, so that a server that cannot read
// containment goes quiet and its gateways fail closed. A stream ends after
// StreamLifetime; the gateway reconnects.
func (h *GatewayHandler) WatchContainment(ctx context.Context, _ *pantherclawv1.WatchContainmentRequest,
	stream pantherclawv1connect.GatewayServiceWatchContainmentServerStream,
) error {
	id, err := identity(ctx)
	if err != nil {
		return err
	}
	if h.hub == nil {
		return connect.NewError(connect.CodeUnavailable, "the containment stream is not configured")
	}
	sub, err := h.hub.Subscribe(id) //nolint:contextcheck // the org poller is shared by streams and outlives this one
	if errors.Is(err, gwapp.ErrTooManyStreams) {
		return connect.NewError(connect.CodeResourceExhausted, err.Error())
	} else if err != nil {
		return err
	}
	defer sub.Close()
	end := time.NewTimer(gwapp.StreamLifetime)
	defer end.Stop()
	beat := time.NewTicker(gwapp.HeartbeatEvery)
	defer beat.Stop()
	var (
		last   gwapp.Containment
		sent   bool
		sentAt time.Time
	)
	for {
		if c, fresh := sub.State(); fresh {
			kind := pantherclawv1.ContainmentStateKind_CONTAINMENT_STATE_KIND_UNSPECIFIED
			switch {
			case !sent:
				kind = pantherclawv1.ContainmentStateKind_CONTAINMENT_STATE_KIND_SNAPSHOT
			case !c.Equal(last):
				kind = pantherclawv1.ContainmentStateKind_CONTAINMENT_STATE_KIND_CHANGE
			case time.Since(sentAt) >= gwapp.HeartbeatEvery, c.VerificationsWaiting && !last.VerificationsWaiting:
				// Verifications that became due go out at once, on a
				// heartbeat: containment itself did not change (G0 M7).
				kind = pantherclawv1.ContainmentStateKind_CONTAINMENT_STATE_KIND_HEARTBEAT
			}
			if kind != pantherclawv1.ContainmentStateKind_CONTAINMENT_STATE_KIND_UNSPECIFIED {
				if err := stream.Send(containmentOf(kind, c)); err != nil {
					return err
				}
				last, sent, sentAt = c, true, time.Now()
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-sub.Done():
			return nil
		case <-end.C:
			return nil
		case <-sub.Changed():
		case <-beat.C:
		}
	}
}

// StreamDeadlines lets the containment stream outlive the listener's write
// timeout, up to its own lifetime; every other call keeps the timeout.
func StreamDeadlines(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == pantherclawv1connect.GatewayServiceWatchContainmentProcedure {
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(gwapp.StreamLifetime + time.Minute))
		}
		next.ServeHTTP(w, r)
	})
}
