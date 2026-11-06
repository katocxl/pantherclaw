// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package aws

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// The simulated SSM-managed instances (G0 M34 D998).
const (
	// Instance and SecondInstance are EC2 instances; ManagedInstance is a
	// hybrid managed node.
	Instance        = "i-0123456789abcdef0"
	SecondInstance  = "i-0fedcba9876543210"
	ManagedInstance = "mi-0123456789abcdef0"

	ssmTargetPrefix = "AmazonSSM."
	// ssmMaxInstances is SendCommand's limit on InstanceIds.
	ssmMaxInstances = 50
)

// ssmDocuments are the documents SendCommand accepts here.
var ssmDocuments = []string{"AWS-RunShellScript", "AWS-RunPowerShellScript"}

// Command is one SendCommand the simulator accepted, for tests. Nothing
// runs anywhere.
type Command struct {
	CommandID    string   `json:"command_id"`
	DocumentName string   `json:"document_name"`
	InstanceIDs  []string `json:"instance_ids"`
	Commands     []string `json:"commands"`
	Comment      string   `json:"comment,omitzero"`
}

// Commands returns every accepted SendCommand, in order.
func (s *Server) Commands() []Command {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.commands)
}

// instanceARN is the resource IAM evaluates for an instance id.
func instanceARN(id string) string {
	if strings.HasPrefix(id, "mi-") {
		return "arn:aws:ssm:" + Region + ":" + Account + ":managed-instance/" + id
	}
	return "arn:aws:ec2:" + Region + ":" + Account + ":instance/" + id
}

// serveSSM answers an AmazonSSM aws-json request. Its caller holds the lock
// and has checked the signature.
func (s *Server) serveSSM(w http.ResponseWriter, body []byte, target string, p principal) {
	action, _ := strings.CutPrefix(target, ssmTargetPrefix)
	var in struct {
		DocumentName string              `json:"DocumentName"`
		InstanceIDs  []string            `json:"InstanceIds"`
		Parameters   map[string][]string `json:"Parameters"`
		Comment      string              `json:"Comment"`
	}
	if json.Unmarshal(body, &in) != nil {
		writeECSError(w, "SerializationException", "the request")
		return
	}
	// IAM evaluates SendCommand on the document and on every instance, and
	// the session policy must allow it on each of them (G0 M34 D1203: a
	// session naming only the instance, or only the document, is refused).
	resources := []string{"arn:aws:ssm:" + Region + "::document/" + in.DocumentName}
	for _, id := range in.InstanceIDs {
		resources = append(resources, instanceARN(id))
	}
	call := Call{Service: p.service, Action: action, Key: p.key, Resource: resources[0]}
	if len(in.InstanceIDs) == 1 {
		call.Resource = resources[1]
	}
	if p.sess != nil {
		call.Policy = p.sess.actions()
	}
	call.Allowed = !slices.ContainsFunc(resources, func(r string) bool { return !s.allowed(p.service, action, r, p.sess) })
	s.calls = append(s.calls, call)
	if !call.Allowed {
		writeECSError(w, "AccessDeniedException", fmt.Sprintf("not authorized to perform %s:%s", p.service, action))
		return
	}
	if p.service+":"+action != "ssm:SendCommand" {
		writeECSError(w, "InvalidAction", "unknown action "+action)
		return
	}
	commands := in.Parameters["commands"]
	switch {
	case !slices.Contains(ssmDocuments, in.DocumentName):
		writeECSError(w, "InvalidDocument", "the document does not exist")
		return
	case len(in.InstanceIDs) == 0 || len(in.InstanceIDs) > ssmMaxInstances ||
		slices.ContainsFunc(in.InstanceIDs, func(id string) bool { return id != Instance && id != SecondInstance && id != ManagedInstance }):
		writeECSError(w, "InvalidInstanceId", "an instance is not valid, not running or not managed by SSM")
		return
	case len(commands) == 0 || len(in.Parameters) != 1:
		writeECSError(w, "InvalidParameters", "the document takes exactly one parameter, commands")
		return
	}
	c := Command{
		CommandID: fmt.Sprintf("%s-%s-%s-%s-%s", random(4), random(2), random(2), random(2), random(6)), DocumentName: in.DocumentName,
		InstanceIDs: slices.Clone(in.InstanceIDs), Commands: slices.Clone(commands), Comment: in.Comment,
	}
	s.commands = append(s.commands, c)
	writeECS(w, map[string]any{"Command": map[string]any{
		"CommandId": c.CommandID, "DocumentName": c.DocumentName, "InstanceIds": c.InstanceIDs, "Comment": c.Comment,
		"Parameters": map[string][]string{"commands": c.Commands}, "Status": "Pending", "StatusDetails": "Pending",
		"RequestedDateTime": float64(p.now.UnixMilli()) / 1000, "TargetCount": len(c.InstanceIDs), "CompletedCount": 0, "ErrorCount": 0,
	}})
}
