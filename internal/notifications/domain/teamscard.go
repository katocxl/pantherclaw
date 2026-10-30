// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"regexp"
	"strings"
)

// Teams approval cards (G0 M20 D256; HR-529). A teams_app channel posts a
// link-only Adaptive Card when a decision is waiting: the same fixed facts
// as a Slack card (HR-314) and one Action.OpenUrl to the authenticated
// approval page. It has no input, no submit action and no other element
// that sends anything back; Teams can never decide anything.

// TeamsAppConfig is a teams_app channel's configuration. ClientSecret is
// input only: it is encrypted and never returned.
type TeamsAppConfig struct {
	// TenantID is the Entra tenant the bot is installed in.
	TenantID string
	// TeamID is the team's General channel id; ChannelID the channel the
	// cards go to.
	TeamID, ChannelID string
	// AppID is the bot's Microsoft App ID; ClientSecret its client secret.
	AppID, ClientSecret string
	// ServiceURL is the Bot Framework service URL the bot posts to.
	ServiceURL string
}

var (
	teamsGUIDPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	teamsChannelPattern = regexp.MustCompile(`^19:[A-Za-z0-9_-]{1,128}@thread\.(tacv2|skype)$`)
)

// Check refuses a configuration that can never be stored; the service
// URL's host is checked by the sender (a Bot Framework host over HTTPS).
func (c TeamsAppConfig) Check() error {
	switch {
	case !teamsGUIDPattern.MatchString(c.TenantID), !teamsGUIDPattern.MatchString(c.AppID),
		!teamsChannelPattern.MatchString(c.TeamID), !teamsChannelPattern.MatchString(c.ChannelID),
		len(c.ClientSecret) < 16 || len(c.ClientSecret) > 512,
		c.ServiceURL == "" || len(c.ServiceURL) > 512:
		return ErrInvalid
	}
	return nil
}

// TeamsCard is a Bot Framework message activity carrying one Adaptive Card.
type TeamsCard struct {
	Type        string            `json:"type"`
	Text        string            `json:"text"`
	Attachments []TeamsAttachment `json:"attachments"`
}

// TeamsAttachment is an Adaptive Card attachment.
type TeamsAttachment struct {
	ContentType string       `json:"contentType"`
	Content     AdaptiveCard `json:"content"`
}

// AdaptiveCard is the card: text blocks and one OpenUrl action.
type AdaptiveCard struct {
	Type    string           `json:"type"`
	Schema  string           `json:"$schema"`
	Version string           `json:"version"`
	Body    []AdaptiveText   `json:"body"`
	Actions []AdaptiveAction `json:"actions"`
}

// AdaptiveText is a TextBlock.
type AdaptiveText struct {
	Type   string `json:"type"`
	Text   string `json:"text"`
	Wrap   bool   `json:"wrap"`
	Weight string `json:"weight,omitzero"`
}

// AdaptiveAction is an Action.OpenUrl.
type AdaptiveAction struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

// teamsText escapes what Teams would read as markdown in a TextBlock.
func teamsText(s string) string {
	r := strings.NewReplacer(`\`, `\`, `*`, `\*`, `_`, `\_`, `[`, `\[`, `]`, `\]`, `<`, "&lt;", `>`, "&gt;", "`", "\\`", `#`, `\#`)
	return r.Replace(s)
}

// TeamsOpenCard is the card of a waiting request (HR-529): the facts and
// one link to the approval page.
func TeamsOpenCard(f CardFacts) TeamsCard {
	h := f.heading("Approval needed")
	body := []AdaptiveText{{Type: "TextBlock", Text: teamsText(h), Wrap: true, Weight: "Bolder"}}
	for _, x := range f.fields(true) {
		body = append(body, AdaptiveText{Type: "TextBlock", Text: teamsText(x.Text), Wrap: true})
	}
	body = append(body, AdaptiveText{Type: "TextBlock", Wrap: true,
		Text: "Decisions are made only on the PantherClaw approval page. Reactions and replies here never count."})
	return TeamsCard{
		Type: "message", Text: teamsText(h + " (reference " + short(f.RequestID) + ")"),
		Attachments: []TeamsAttachment{{
			ContentType: "application/vnd.microsoft.card.adaptive",
			Content: AdaptiveCard{
				Type: "AdaptiveCard", Schema: "http://adaptivecards.io/schemas/adaptive-card.json", Version: "1.4", Body: body,
				Actions: []AdaptiveAction{{Type: "Action.OpenUrl", Title: "Open in PantherClaw", URL: f.Link}},
			},
		}},
	}
}
