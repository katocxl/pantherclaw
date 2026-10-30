// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package aws

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// The simulated ECS service.
const (
	Cluster = "prod"
	Service = "web"
	// ServiceTarget is the service as a pc.aws.ecs target id.
	ServiceTarget = Cluster + "/" + Service

	ecsTargetPrefix = "AmazonEC2ContainerServiceV20141113."
	ecsContentType  = "application/x-amz-json-1.1"
)

// Rollout states, as ECS reports them.
const (
	RolloutInProgress = "IN_PROGRESS"
	RolloutCompleted  = "COMPLETED"
	RolloutFailed     = "FAILED"
)

// TaskDefinition is the ARN of a revision of the simulated task definition.
func TaskDefinition(revision int) string {
	return "arn:aws:ecs:" + Region + ":" + Account + ":task-definition/" + Service + ":" + strconv.Itoa(revision)
}

// serviceARN is the ARN of a service in the simulated account.
func serviceARN(cluster, service string) string {
	return "arn:aws:ecs:" + Region + ":" + Account + ":service/" + cluster + "/" + service
}

// Deployment is one deployment of the service, as DescribeServices lists it.
type Deployment struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	TaskDefinition string `json:"taskDefinition"`
	RolloutState   string `json:"rolloutState,omitzero"`
}

type controller struct {
	Type string `json:"type"`
}

type ecsService struct {
	ServiceArn           string       `json:"serviceArn"`
	ServiceName          string       `json:"serviceName"`
	Status               string       `json:"status"`
	TaskDefinition       string       `json:"taskDefinition"`
	DeploymentController *controller  `json:"deploymentController,omitzero"`
	Deployments          []Deployment `json:"deployments"`
}

func newECSService() *ecsService {
	return &ecsService{
		ServiceArn: serviceARN(Cluster, Service), ServiceName: Service, Status: "ACTIVE", TaskDefinition: TaskDefinition(1),
		DeploymentController: &controller{Type: "ECS"},
		Deployments:          []Deployment{{ID: "ecs-svc/1", Status: "PRIMARY", TaskDefinition: TaskDefinition(1), RolloutState: RolloutCompleted}},
	}
}

// SetRollout sets the rollout state of the newest deployment; "" is a
// service for which ECS reports none, such as one behind a Classic Load
// Balancer.
func (s *Server) SetRollout(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ecs.Deployments[0].RolloutState = state
}

// SetController sets the service's deployment controller: "ECS",
// "CODE_DEPLOY" or "EXTERNAL", or "" for a service that names none.
func (s *Server) SetController(kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ecs.DeploymentController = nil
	if kind != "" {
		s.ecs.DeploymentController = &controller{Type: kind}
	}
}

// AddDeployment adds an older deployment to the end of the service's list.
func (s *Server) AddDeployment(taskDefinition, state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := fmt.Sprintf("ecs-svc/%d", len(s.ecs.Deployments)+1)
	s.ecs.Deployments = append(s.ecs.Deployments, Deployment{ID: id, Status: "ACTIVE", TaskDefinition: taskDefinition, RolloutState: state})
}

// ServiceTaskDefinition is the task definition the service names now.
func (s *Server) ServiceTaskDefinition() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ecs.TaskDefinition
}

// serveECS answers an aws-json request, by its X-Amz-Target. Its caller holds
// the lock and has checked the signature.
func (s *Server) serveECS(w http.ResponseWriter, body []byte, target, service, key string, sess *session) {
	action, ok := strings.CutPrefix(target, ecsTargetPrefix)
	var in struct {
		Cluster        string   `json:"cluster"`
		Service        string   `json:"service"`
		Services       []string `json:"services"`
		TaskDefinition string   `json:"taskDefinition"`
	}
	if !ok || json.Unmarshal(body, &in, json.RejectUnknownMembers(true)) != nil {
		writeECSError(w, "SerializationException", "the request")
		return
	}
	name := in.Service
	if len(in.Services) == 1 {
		name = in.Services[0]
	}
	call := Call{Service: service, Action: action, Key: key, Resource: serviceARN(in.Cluster, name)}
	if sess != nil {
		call.Policy = sess.actions()
	}
	call.Allowed = s.allowed(service, action, call.Resource, sess)
	s.calls = append(s.calls, call)
	if !call.Allowed {
		writeECSError(w, "AccessDeniedException", fmt.Sprintf("not authorized to perform %s:%s", service, action))
		return
	}
	found := in.Cluster == Cluster && name == Service
	switch service + ":" + action {
	case "ecs:UpdateService":
		if !found {
			writeECSError(w, "ServiceNotFoundException", "Service not found.")
			return
		}
		s.update(in.TaskDefinition)
		writeECS(w, map[string]any{"service": s.ecs})
	case "ecs:DescribeServices":
		if !found || len(in.Services) != 1 {
			writeECS(w, map[string]any{"services": []any{}, "failures": []map[string]string{{"arn": call.Resource, "reason": "MISSING"}}})
			return
		}
		writeECS(w, map[string]any{"services": []*ecsService{s.ecs}, "failures": []any{}})
	default:
		writeECSError(w, "InvalidAction", "unknown action "+action)
	}
}

// update starts a rollout of taskDefinition, the newest deployment first.
// The same task definition again starts nothing, as ECS does not.
func (s *Server) update(taskDefinition string) {
	if taskDefinition == s.ecs.TaskDefinition {
		return
	}
	s.ecs.TaskDefinition = taskDefinition
	for i := range s.ecs.Deployments {
		s.ecs.Deployments[i].Status = "ACTIVE"
	}
	id := fmt.Sprintf("ecs-svc/%d", len(s.ecs.Deployments)+1)
	s.ecs.Deployments = slices.Insert(s.ecs.Deployments, 0, Deployment{
		ID: id, Status: "PRIMARY", TaskDefinition: taskDefinition, RolloutState: RolloutInProgress,
	})
}

func writeECS(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", ecsContentType)
	_ = json.MarshalWrite(w, v)
}

// writeECSError answers as ECS does: every error here is a 400.
func writeECSError(w http.ResponseWriter, kind, message string) {
	w.Header().Set("Content-Type", ecsContentType)
	w.WriteHeader(http.StatusBadRequest)
	_ = json.MarshalWrite(w, map[string]string{"__type": kind, "message": message})
}
