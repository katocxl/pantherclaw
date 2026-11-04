// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/kube"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The M32 gateway stream's wiring (G0 M32 D968): gateway enrollment from a
// bound pod's projected token, and the binding's administration.

var m32GatewayProcedures = map[string]td.Permission{
	pantherclawv1connect.GatewayAdminServiceSetGatewayKubernetesBindingProcedure:   "gateway.manage",
	pantherclawv1connect.GatewayAdminServiceClearGatewayKubernetesBindingProcedure: "gateway.manage",
}

// Setting a binding adds a way to enroll (a change); clearing one removes
// it (safety, like revoking a certificate).
var m32GatewayClasses = map[string]entitlements.Class{
	pantherclawv1connect.GatewayAdminServiceSetGatewayKubernetesBindingProcedure:   entitlements.ClassChange,
	pantherclawv1connect.GatewayAdminServiceClearGatewayKubernetesBindingProcedure: entitlements.ClassSafety,
}

func init() {
	maps.Copy(procedurePermissions, m32GatewayProcedures)
	maps.Copy(procedureClasses, m32GatewayClasses)
}

// wireM32Gateways lets gateways bound to a service account of a configured
// cluster enroll from their pods' projected tokens. Without a configured
// cluster nothing changes: every projected-token enrollment is refused.
func wireM32Gateways(cfg *Config, m6 *m6Services) error {
	if m6 == nil || len(cfg.Identity.KubernetesClusters) == 0 {
		return nil
	}
	dir, err := kube.NewDirectory(cfg.Identity.KubernetesClusters)
	if err != nil {
		return err
	}
	client, err := kube.NewClient(dir, attestTimeout)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(cfg.Identity.KubernetesClusters))
	for _, c := range cfg.Identity.KubernetesClusters {
		names = append(names, c.Name)
	}
	m6.gateways.WithKubernetes(client, dir, names)
	return nil
}
