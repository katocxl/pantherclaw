// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package review holds the parts of the Kubernetes admission.k8s.io/v1
// AdmissionReview and core/v1 Pod that the admission webhook reads and
// writes (G0 M32 D967). Standard library only: the JSON field names are
// Kubernetes' own; fields the webhook never reads are left out and ignored.
package review

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
)

// APIVersion and Kind of every review the webhook accepts and answers.
const (
	APIVersion = "admission.k8s.io/v1"
	Kind       = "AdmissionReview"
)

// AdmissionReview is the envelope of a request and of its response.
type AdmissionReview struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Request    *Request  `json:"request,omitempty"`
	Response   *Response `json:"response,omitempty"`
}

// GroupVersionResource names a resource.
type GroupVersionResource struct {
	Group    string `json:"group"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
}

// GroupVersionKind names a kind.
type GroupVersionKind struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

// UserInfo is who asked the API server.
type UserInfo struct {
	Username string   `json:"username"`
	UID      string   `json:"uid"`
	Groups   []string `json:"groups"`
}

// Operations the webhook decides on.
const (
	OperationCreate = "CREATE"
	OperationUpdate = "UPDATE"
)

// Request is one admission request.
type Request struct {
	UID         string               `json:"uid"`
	Kind        GroupVersionKind     `json:"kind"`
	Resource    GroupVersionResource `json:"resource"`
	SubResource string               `json:"subResource"`
	Name        string               `json:"name"`
	Namespace   string               `json:"namespace"`
	Operation   string               `json:"operation"`
	UserInfo    UserInfo             `json:"userInfo"`
	Object      jsontext.Value       `json:"object"`
	OldObject   jsontext.Value       `json:"oldObject"`
	DryRun      *bool                `json:"dryRun"`
}

// IsDryRun reports a dry run: nothing is persisted, so the webhook writes
// nothing either.
func (r *Request) IsDryRun() bool { return r.DryRun != nil && *r.DryRun }

// Status is the reason a request was denied (a metav1.Status subset).
type Status struct {
	Code    int32  `json:"code,omitzero"`
	Message string `json:"message,omitempty"`
	// Reason carries the webhook's refusal code (K8S_*).
	Reason string `json:"reason,omitempty"`
}

// Response is the webhook's answer.
type Response struct {
	UID     string  `json:"uid"`
	Allowed bool    `json:"allowed"`
	Result  *Status `json:"status,omitempty"`
}

// ErrMalformed is a body that is not an admission.k8s.io/v1 request.
var ErrMalformed = errors.New("review: not an admission.k8s.io/v1 AdmissionReview request")

// Parse decodes a request review. It refuses another version or kind, a
// missing request or uid.
func Parse(body []byte) (*AdmissionReview, error) {
	var r AdmissionReview
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, errors.Join(ErrMalformed, err)
	}
	if r.APIVersion != APIVersion || r.Kind != Kind || r.Request == nil || r.Request.UID == "" {
		return nil, ErrMalformed
	}
	return &r, nil
}

// Answer is the response review to req.
func Answer(req *Request, allowed bool, status *Status) AdmissionReview {
	return AdmissionReview{
		APIVersion: APIVersion, Kind: Kind,
		Response: &Response{UID: req.UID, Allowed: allowed, Result: status},
	}
}

// ObjectMeta is the part of a pod's metadata the webhook reads.
type ObjectMeta struct {
	Name         string            `json:"name"`
	GenerateName string            `json:"generateName"`
	Namespace    string            `json:"namespace"`
	Labels       map[string]string `json:"labels"`
}

// Pod is a core/v1 Pod.
type Pod struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     PodSpec    `json:"spec"`
}

// PodSpec is the part of a pod spec the webhook reads.
type PodSpec struct {
	ServiceAccountName           string      `json:"serviceAccountName"`
	AutomountServiceAccountToken *bool       `json:"automountServiceAccountToken"`
	HostNetwork                  bool        `json:"hostNetwork"`
	HostPID                      bool        `json:"hostPID"`
	HostIPC                      bool        `json:"hostIPC"`
	Containers                   []Container `json:"containers"`
	InitContainers               []Container `json:"initContainers"`
	EphemeralContainers          []Container `json:"ephemeralContainers"`
	Volumes                      []Volume    `json:"volumes"`
}

// RestartPolicyAlways on an init container makes it a native sidecar.
const RestartPolicyAlways = "Always"

// Container is a container, init container or ephemeral container.
type Container struct {
	Name            string           `json:"name"`
	Image           string           `json:"image"`
	RestartPolicy   *string          `json:"restartPolicy"`
	SecurityContext *SecurityContext `json:"securityContext"`
	VolumeMounts    []VolumeMount    `json:"volumeMounts"`
}

// IsSidecar reports an init container with restartPolicy Always.
func (c Container) IsSidecar() bool {
	return c.RestartPolicy != nil && *c.RestartPolicy == RestartPolicyAlways
}

// SecurityContext is the part of a container's security context the
// webhook reads.
type SecurityContext struct {
	Privileged *bool `json:"privileged"`
}

// VolumeMount mounts a volume into a container.
type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
}

// Volume is a pod volume.
type Volume struct {
	Name      string           `json:"name"`
	HostPath  *HostPathVolume  `json:"hostPath"`
	Projected *ProjectedVolume `json:"projected"`
}

// HostPathVolume is a hostPath volume.
type HostPathVolume struct {
	Path string `json:"path"`
}

// ProjectedVolume is a projected volume.
type ProjectedVolume struct {
	Sources []VolumeProjection `json:"sources"`
}

// VolumeProjection is one source of a projected volume.
type VolumeProjection struct {
	ServiceAccountToken *ServiceAccountTokenProjection `json:"serviceAccountToken"`
}

// ServiceAccountTokenProjection is a projected service-account token.
type ServiceAccountTokenProjection struct {
	Audience          string `json:"audience"`
	ExpirationSeconds *int64 `json:"expirationSeconds"`
	Path              string `json:"path"`
}

// ParsePod decodes a review's object as a pod.
func ParsePod(raw jsontext.Value) (*Pod, error) {
	if len(raw) == 0 {
		return nil, ErrMalformed
	}
	var p Pod
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, errors.Join(ErrMalformed, err)
	}
	return &p, nil
}
