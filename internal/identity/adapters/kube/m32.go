// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package kube

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

// PodImages are a pod's image ids by kind of container (G0 M32 D970b):
// the app containers' and the init containers', native sidecars among
// them, from the pod's status.
type PodImages struct {
	// Found is false for a missing pod.
	Found bool
	Phase string
	// Apps are the app containers by name, Inits the init containers.
	Apps  map[string]string
	Inits map[string]InitImage
}

// InitImage is one init container: its image id and whether it is a
// native sidecar (restartPolicy Always).
type InitImage struct {
	ImageID string
	Sidecar bool
}

// PodImages reads one pod's containers and their image ids, including the
// init containers (initContainerStatuses), which Pod does not read. A
// missing pod is a PodImages with Found false.
func (c *Client) PodImages(ctx context.Context, clusterName, namespace, name string) (PodImages, error) {
	cl, err := c.cluster(clusterName)
	if err != nil {
		return PodImages{}, err
	}
	type status struct {
		Name    string `json:"name"`
		ImageID string `json:"imageID"`
	}
	var out struct {
		Spec struct {
			InitContainers []struct {
				Name          string `json:"name"`
				RestartPolicy string `json:"restartPolicy"`
			} `json:"initContainers"`
		} `json:"spec"`
		Status struct {
			Phase                 string   `json:"phase"`
			ContainerStatuses     []status `json:"containerStatuses"`
			InitContainerStatuses []status `json:"initContainerStatuses"`
		} `json:"status"`
	}
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(name)
	if err := cl.do(ctx, http.MethodGet, path, nil, &out); errors.Is(err, errNotFound) {
		return PodImages{}, nil
	} else if err != nil {
		return PodImages{}, err
	}
	p := PodImages{Found: true, Phase: out.Status.Phase, Apps: map[string]string{}, Inits: map[string]InitImage{}}
	for _, s := range out.Status.ContainerStatuses {
		p.Apps[s.Name] = s.ImageID
	}
	sidecar := map[string]bool{}
	for _, ic := range out.Spec.InitContainers {
		sidecar[ic.Name] = ic.RestartPolicy == "Always"
	}
	for _, s := range out.Status.InitContainerStatuses {
		p.Inits[s.Name] = InitImage{ImageID: s.ImageID, Sidecar: sidecar[s.Name]}
	}
	return p, nil
}

// NetworkPolicy is the part of a NetworkPolicy the closure check reads
// (G0 M32 D970).
type NetworkPolicy struct {
	Name        string
	PodSelector LabelSelector
	PolicyTypes []string
	Egress      []EgressRule
}

// LabelSelector is a selector's labels; Expressions counts its
// matchExpressions, which the check does not interpret.
type LabelSelector struct {
	MatchLabels map[string]string
	Expressions int
}

// Empty reports whether the selector selects everything.
func (s LabelSelector) Empty() bool { return len(s.MatchLabels) == 0 && s.Expressions == 0 }

// EgressRule is one egress rule.
type EgressRule struct {
	To    []Peer
	Ports []Port
}

// Peer is one egress peer.
type Peer struct {
	PodSelector       *LabelSelector
	NamespaceSelector *LabelSelector
	// CIDR and Except are an ipBlock peer's.
	CIDR   string
	Except []string
}

// Port is one egress port; an empty Protocol is TCP. Port is the
// number or name as written; EndPort is set for a range.
type Port struct {
	Protocol string
	Port     string
	EndPort  int
}

// NetworkPolicies lists a namespace's NetworkPolicies with the cluster's
// reviewer credential.
func (c *Client) NetworkPolicies(ctx context.Context, clusterName, namespace string) ([]NetworkPolicy, error) {
	cl, err := c.cluster(clusterName)
	if err != nil {
		return nil, err
	}
	type selector struct {
		MatchLabels      map[string]string `json:"matchLabels"`
		MatchExpressions []any             `json:"matchExpressions"`
	}
	var out struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				PodSelector selector `json:"podSelector"`
				PolicyTypes []string `json:"policyTypes"`
				Egress      []struct {
					To []struct {
						PodSelector       *selector `json:"podSelector"`
						NamespaceSelector *selector `json:"namespaceSelector"`
						IPBlock           *struct {
							CIDR   string   `json:"cidr"`
							Except []string `json:"except"`
						} `json:"ipBlock"`
					} `json:"to"`
					Ports []struct {
						Protocol string `json:"protocol"`
						Port     any    `json:"port"`
						EndPort  int    `json:"endPort"`
					} `json:"ports"`
				} `json:"egress"`
			} `json:"spec"`
		} `json:"items"`
	}
	path := "/apis/networking.k8s.io/v1/namespaces/" + url.PathEscape(namespace) + "/networkpolicies"
	if err := cl.do(ctx, http.MethodGet, path, nil, &out); errors.Is(err, errNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	sel := func(s *selector) *LabelSelector {
		if s == nil {
			return nil
		}
		return &LabelSelector{MatchLabels: s.MatchLabels, Expressions: len(s.MatchExpressions)}
	}
	var nps []NetworkPolicy
	for _, it := range out.Items {
		np := NetworkPolicy{Name: it.Metadata.Name, PodSelector: *sel(&it.Spec.PodSelector), PolicyTypes: it.Spec.PolicyTypes}
		for _, e := range it.Spec.Egress {
			var r EgressRule
			for _, t := range e.To {
				p := Peer{PodSelector: sel(t.PodSelector), NamespaceSelector: sel(t.NamespaceSelector)}
				if t.IPBlock != nil {
					p.CIDR, p.Except = t.IPBlock.CIDR, t.IPBlock.Except
				}
				r.To = append(r.To, p)
			}
			for _, pt := range e.Ports {
				port := ""
				switch v := pt.Port.(type) {
				case string:
					port = v
				case float64:
					port = formatPort(v)
				}
				r.Ports = append(r.Ports, Port{Protocol: pt.Protocol, Port: port, EndPort: pt.EndPort})
			}
			np.Egress = append(np.Egress, r)
		}
		nps = append(nps, np)
	}
	return nps, nil
}

func formatPort(v float64) string {
	if v < 1 || v > 65535 || v != float64(int(v)) {
		return "?"
	}
	return strconv.Itoa(int(v))
}
