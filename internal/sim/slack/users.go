// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package slack

import (
	"net/http"
	"strings"
)

// User is one member of the simulated workspace, for users.lookupByEmail
// and conversations.open (approval DMs, G0 M20 D256).
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	// Team is the user's workspace (default the simulator's).
	Team           string `json:"team_id,omitzero"`
	Deleted        bool   `json:"deleted,omitzero"`
	Bot            bool   `json:"is_bot,omitzero"`
	Restricted     bool   `json:"is_restricted,omitzero"`
	EmailConfirmed bool   `json:"is_email_confirmed"`
}

// SetUser adds or replaces a member of the workspace.
func (s *Server) SetUser(u User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.users == nil {
		s.users = map[string]User{}
	}
	s.users[u.ID] = u
}

// DMChannel is the id of the DM channel conversations.open gives for user.
func DMChannel(user string) string {
	id := "D" + strings.TrimLeft(user, "UW")
	if len(id) < 9 {
		id += strings.Repeat("0", 9-len(id))
	}
	return id[:min(len(id), 13)]
}

// lookupByEmail answers users.lookupByEmail; s.mu is held.
func (s *Server) lookupByEmail(w http.ResponseWriter, in input) {
	email := strings.ToLower(in.str("email"))
	for _, u := range s.users {
		if strings.ToLower(u.Email) != email || email == "" {
			continue
		}
		team := u.Team
		if team == "" {
			team = s.team
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": map[string]any{
			"id": u.ID, "team_id": team, "deleted": u.Deleted, "is_bot": u.Bot, "is_restricted": u.Restricted,
			"is_ultra_restricted": false, "is_email_confirmed": u.EmailConfirmed, "profile": map[string]any{"email": u.Email},
		}})
		return
	}
	writeJSON(w, http.StatusOK, fail("users_not_found"))
}

// openDM answers conversations.open for one user: the DM channel, which
// the bot may then post to; s.mu is held.
func (s *Server) openDM(w http.ResponseWriter, in input) {
	u, ok := s.users[in.str("users")]
	if !ok || u.Deleted {
		writeJSON(w, http.StatusOK, fail("user_not_found"))
		return
	}
	id := DMChannel(u.ID)
	s.channels[id] = Channel{ID: id, Name: u.ID, Private: true, Member: true}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "channel": map[string]any{"id": id}})
}
