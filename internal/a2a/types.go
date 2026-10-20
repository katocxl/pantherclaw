// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package a2a holds the parts of the A2A protocol 1.0 that PantherClaw
// speaks (G0 M14 D30–D33): the wire objects, the agent card with its
// digest and signatures, and the method table of the JSON-RPC and
// HTTP+JSON bindings. The gateway face, the dispatch, the server's card
// pinning and the simulator share it.
package a2a

// Protocol constants (A2A 1.0 §3.6, §8.2, §11).
const (
	// Version is the protocol version PantherClaw speaks.
	Version = "1.0"
	// HeaderVersion carries the version on every request.
	HeaderVersion = "A2A-Version"
	// ContentType is the media type of HTTP+JSON bodies.
	ContentType = "application/a2a+json"
	// CardPath is the well-known agent card location.
	CardPath = "/.well-known/agent-card.json"
)

// Protocol bindings an interface declares.
const (
	BindingJSONRPC  = "JSONRPC"
	BindingHTTPJSON = "HTTP+JSON"
	BindingGRPC     = "GRPC"
)

// Methods (A2A 1.0 §5.3).
const (
	MethodSendMessage          = "SendMessage"
	MethodSendStreamingMessage = "SendStreamingMessage"
	MethodGetTask              = "GetTask"
	MethodListTasks            = "ListTasks"
	MethodCancelTask           = "CancelTask"
	MethodSubscribeToTask      = "SubscribeToTask"
	MethodCreatePushConfig     = "CreateTaskPushNotificationConfig"
	MethodGetPushConfig        = "GetTaskPushNotificationConfig"
	MethodListPushConfigs      = "ListTaskPushNotificationConfigs"
	MethodDeletePushConfig     = "DeleteTaskPushNotificationConfig"
	MethodGetExtendedCard      = "GetExtendedAgentCard"
)

// Streaming reports whether method answers with an event stream.
func Streaming(method string) bool {
	return method == MethodSendStreamingMessage || method == MethodSubscribeToTask
}

// Unsupported reports whether method is one PantherClaw never relays:
// push notification configurations and the extended card (D31).
func Unsupported(method string) bool {
	switch method {
	case MethodCreatePushConfig, MethodGetPushConfig, MethodListPushConfigs, MethodDeletePushConfig, MethodGetExtendedCard:
		return true
	}
	return false
}

// Task states (A2A 1.0 §4.1.3).
const (
	StateSubmitted     = "TASK_STATE_SUBMITTED"
	StateWorking       = "TASK_STATE_WORKING"
	StateCompleted     = "TASK_STATE_COMPLETED"
	StateFailed        = "TASK_STATE_FAILED"
	StateCanceled      = "TASK_STATE_CANCELED"
	StateInputRequired = "TASK_STATE_INPUT_REQUIRED"
	StateRejected      = "TASK_STATE_REJECTED"
	StateAuthRequired  = "TASK_STATE_AUTH_REQUIRED"
)

// Terminal reports whether a task in state s can change no more.
func Terminal(s string) bool {
	return s == StateCompleted || s == StateFailed || s == StateCanceled || s == StateRejected
}

// Interrupted reports whether a task in state s waits for its client.
func Interrupted(s string) bool { return s == StateInputRequired || s == StateAuthRequired }

// Roles.
const (
	RoleUser  = "ROLE_USER"
	RoleAgent = "ROLE_AGENT"
)

// Error codes (A2A 1.0 §5.4) and the JSON-RPC 2.0 codes.
const (
	CodeParse                = -32700
	CodeInvalidRequest       = -32600
	CodeMethodNotFound       = -32601
	CodeInvalidParams        = -32602
	CodeInternal             = -32603
	CodeTaskNotFound         = -32001
	CodeTaskNotCancelable    = -32002
	CodePushNotSupported     = -32003
	CodeUnsupportedOperation = -32004
	CodeContentType          = -32005
	CodeVersionNotSupported  = -32009
)

// Part is one piece of a message or artifact: exactly one of Text, Raw,
// URL or Data (§4.1.6). PantherClaw relays text parts only (D31).
type Part struct {
	Text      *string        `json:"text,omitzero"`
	Raw       []byte         `json:"raw,omitzero"`
	URL       *string        `json:"url,omitzero"`
	Data      any            `json:"data,omitzero"`
	Metadata  map[string]any `json:"metadata,omitzero"`
	Filename  string         `json:"filename,omitzero"`
	MediaType string         `json:"mediaType,omitzero"`
}

// TextPart returns a text part.
func TextPart(s string) Part { return Part{Text: &s} }

// IsText reports whether p is a text part and nothing else.
func (p Part) IsText() bool {
	return p.Text != nil && p.Raw == nil && p.URL == nil && p.Data == nil && p.Filename == ""
}

// Message is one message (§4.1.4).
type Message struct {
	MessageID        string         `json:"messageId"`
	ContextID        string         `json:"contextId,omitzero"`
	TaskID           string         `json:"taskId,omitzero"`
	Role             string         `json:"role"`
	Parts            []Part         `json:"parts"`
	Metadata         map[string]any `json:"metadata,omitzero"`
	Extensions       []string       `json:"extensions,omitzero"`
	ReferenceTaskIDs []string       `json:"referenceTaskIds,omitzero"`
}

// Text joins the message's text parts.
func (m Message) Text() string {
	var s string
	for _, p := range m.Parts {
		if p.Text != nil {
			s += *p.Text
		}
	}
	return s
}

// SendConfiguration is a send request's configuration (§4.3.1).
type SendConfiguration struct {
	AcceptedOutputModes []string `json:"acceptedOutputModes,omitzero"`
	HistoryLength       *int32   `json:"historyLength,omitzero"`
	Blocking            bool     `json:"blocking,omitzero"`
}

// SendMessageRequest is SendMessage's and SendStreamingMessage's request.
type SendMessageRequest struct {
	Tenant        string             `json:"tenant,omitzero"`
	Message       Message            `json:"message"`
	Configuration *SendConfiguration `json:"configuration,omitzero"`
	Metadata      map[string]any     `json:"metadata,omitzero"`
}

// TaskStatus is a task's status.
type TaskStatus struct {
	State     string   `json:"state"`
	Message   *Message `json:"message,omitzero"`
	Timestamp string   `json:"timestamp,omitzero"`
}

// Artifact is an output of a task.
type Artifact struct {
	ArtifactID  string         `json:"artifactId"`
	Name        string         `json:"name,omitzero"`
	Description string         `json:"description,omitzero"`
	Parts       []Part         `json:"parts"`
	Metadata    map[string]any `json:"metadata,omitzero"`
}

// Task is one task (§4.1.1).
type Task struct {
	ID        string         `json:"id"`
	ContextID string         `json:"contextId,omitzero"`
	Status    TaskStatus     `json:"status"`
	Artifacts []Artifact     `json:"artifacts,omitzero"`
	History   []Message      `json:"history,omitzero"`
	Metadata  map[string]any `json:"metadata,omitzero"`
}

// TaskStatusUpdateEvent is a streamed status change.
type TaskStatusUpdateEvent struct {
	TaskID    string         `json:"taskId"`
	ContextID string         `json:"contextId,omitzero"`
	Status    TaskStatus     `json:"status"`
	Metadata  map[string]any `json:"metadata,omitzero"`
}

// TaskArtifactUpdateEvent is a streamed artifact.
type TaskArtifactUpdateEvent struct {
	TaskID    string         `json:"taskId"`
	ContextID string         `json:"contextId,omitzero"`
	Artifact  Artifact       `json:"artifact"`
	Append    bool           `json:"append,omitzero"`
	LastChunk bool           `json:"lastChunk,omitzero"`
	Metadata  map[string]any `json:"metadata,omitzero"`
}

// SendMessageResponse is SendMessage's answer: a task or a message.
type SendMessageResponse struct {
	Task    *Task    `json:"task,omitzero"`
	Message *Message `json:"message,omitzero"`
}

// StreamResponse is one streamed event: exactly one member is set.
type StreamResponse struct {
	Task           *Task                    `json:"task,omitzero"`
	Message        *Message                 `json:"message,omitzero"`
	StatusUpdate   *TaskStatusUpdateEvent   `json:"statusUpdate,omitzero"`
	ArtifactUpdate *TaskArtifactUpdateEvent `json:"artifactUpdate,omitzero"`
}

// TaskID returns the task the event belongs to, or "".
func (e StreamResponse) TaskID() string {
	switch {
	case e.Task != nil:
		return e.Task.ID
	case e.StatusUpdate != nil:
		return e.StatusUpdate.TaskID
	case e.ArtifactUpdate != nil:
		return e.ArtifactUpdate.TaskID
	case e.Message != nil:
		return e.Message.TaskID
	}
	return ""
}

// GetTaskRequest, CancelTaskRequest and SubscribeToTaskRequest name a task.
type GetTaskRequest struct {
	Tenant        string `json:"tenant,omitzero"`
	ID            string `json:"id"`
	HistoryLength *int32 `json:"historyLength,omitzero"`
}

// TaskIDRequest is CancelTask's and SubscribeToTask's request.
type TaskIDRequest struct {
	Tenant string `json:"tenant,omitzero"`
	ID     string `json:"id"`
}

// ListTasksRequest is ListTasks' request.
type ListTasksRequest struct {
	Tenant    string `json:"tenant,omitzero"`
	ContextID string `json:"contextId,omitzero"`
	Status    string `json:"status,omitzero"`
	PageSize  int32  `json:"pageSize,omitzero"`
	PageToken string `json:"pageToken,omitzero"`
}

// ListTasksResponse is ListTasks' answer.
type ListTasksResponse struct {
	Tasks         []Task `json:"tasks"`
	TotalSize     int32  `json:"totalSize"`
	PageSize      int32  `json:"pageSize"`
	NextPageToken string `json:"nextPageToken"`
}

// RPCRequest is a JSON-RPC 2.0 request.
type RPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitzero"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitzero"`
}

// RPCError is a JSON-RPC 2.0 error.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitzero"`
}

// RPCResponse is a JSON-RPC 2.0 response.
type RPCResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitzero"`
	Error   *RPCError `json:"error,omitzero"`
}

// HTTPStatus is the HTTP+JSON status of an A2A error code (§5.4).
func HTTPStatus(code int) int {
	switch code {
	case CodeTaskNotFound, CodeMethodNotFound:
		return 404
	case CodeInternal:
		return 500
	}
	return 400
}
