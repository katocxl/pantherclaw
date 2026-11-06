// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	binenc "encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf16"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// `pclaw browser policy generate` writes the Chrome policy that deploys the
// managed extension (G0 M33 D983, HR-755): force-installed and pinned from
// the given update URL, incognito and guest mode off (an extension that is
// not allowed in incognito, or a guest profile, would leave the agent a
// browser nothing decides), and the extension's managed configuration with
// the native host name and the marked clicks of the org's browser sites. It
// only writes two files; it installs nothing.

func init() {
	commands["browser policy generate"] = command{
		usage: "browser policy generate --extension-id ID --update-url URL --out DIR [--host-name NAME]",
		run:   browserPolicyGenerate,
	}
}

// hostNamePattern is a native messaging host name as Chrome accepts it.
var hostNamePattern = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*$`)

// chromeClickRule is one entry of the extension's click_rules.
type chromeClickRule struct {
	Host              string   `json:"host"`
	IncludeSubdomains bool     `json:"include_subdomains"`
	Selectors         []string `json:"selectors"`
}

// chromeExtensionPolicy is the extension's managed configuration.
type chromeExtensionPolicy struct {
	HostName   string            `json:"host_name"`
	ClickRules []chromeClickRule `json:"click_rules"`
}

// chromeInstall is the ExtensionSettings entry of the extension.
type chromeInstall struct {
	InstallationMode string `json:"installation_mode"`
	UpdateURL        string `json:"update_url"`
	ToolbarPin       string `json:"toolbar_pin"`
}

func browserPolicyGenerate(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("browser policy generate", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	extID := fs.String("extension-id", "", "the extension's id")
	updateURL := fs.String("update-url", "", "the update manifest URL the extension installs from (https)")
	out := fs.String("out", "", "the directory to write chrome-policy.json and chrome-policy.reg to")
	hostName := fs.String("host-name", browserHostName, "the native messaging host name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *extID == "" || *updateURL == "" || *out == "" {
		return errUsage
	}
	if !extensionIDPattern.MatchString(*extID) {
		return fmt.Errorf("--extension-id %q is not a Chrome extension id", *extID)
	}
	if u, err := url.Parse(*updateURL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("--update-url must be an absolute https URL")
	}
	if !hostNamePattern.MatchString(*hostName) {
		return fmt.Errorf("--host-name %q is not a native messaging host name", *hostName)
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	res, err := pantherclawv1connect.NewBrowserServiceClient(s.connect()).ListBrowserSites(ctx, &pantherclawv1.ListBrowserSitesRequest{})
	if err != nil {
		return fmt.Errorf("list browser sites: %w", err)
	}
	ext := chromeExtensionPolicy{HostName: *hostName, ClickRules: []chromeClickRule{}}
	for _, site := range res.GetSites() {
		if len(site.GetClickSelectors()) > 0 {
			ext.ClickRules = append(ext.ClickRules, chromeClickRule{
				Host: site.GetHost(), IncludeSubdomains: site.GetIncludeSubdomains(), Selectors: site.GetClickSelectors(),
			})
		}
	}
	settings := map[string]chromeInstall{*extID: {InstallationMode: "force_installed", UpdateURL: *updateURL, ToolbarPin: "force_pinned"}}

	policy, err := json.Marshal(map[string]any{
		"ExtensionSettings":         settings,
		"IncognitoModeAvailability": 1,
		"BrowserGuestModeEnabled":   false,
		"3rdparty":                  map[string]any{"extensions": map[string]any{*extID: ext}},
	}, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	settingsJSON, err := json.Marshal(settings, json.Deterministic(true))
	if err != nil {
		return err
	}
	rulesJSON, err := json.Marshal(ext.ClickRules, json.Deterministic(true))
	if err != nil {
		return err
	}
	// The same policy goes under Chrome's and Chromium's roots: a managed
	// Chromium build reads only its own.
	var reg strings.Builder
	reg.WriteString("Windows Registry Editor Version 5.00\r\n")
	for _, root := range []string{
		`HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome`,
		`HKEY_LOCAL_MACHINE\Software\Policies\Chromium`,
	} {
		reg.WriteString("\r\n[" + root + "]\r\n")
		reg.WriteString(`"ExtensionSettings"=` + regString(string(settingsJSON)) + "\r\n")
		reg.WriteString(`"IncognitoModeAvailability"=dword:00000001` + "\r\n")
		reg.WriteString(`"BrowserGuestModeEnabled"=dword:00000000` + "\r\n\r\n")
		reg.WriteString("[" + root + `\3rdparty\extensions\` + *extID + `\policy]` + "\r\n")
		reg.WriteString(`"host_name"=` + regString(*hostName) + "\r\n")
		reg.WriteString(`"click_rules"=` + regString(string(rulesJSON)) + "\r\n")
	}

	if err := os.MkdirAll(*out, 0o755); err != nil { //nolint:gosec // G301: policy files are not secret
		return err
	}
	jsonPath, regPath := filepath.Join(*out, "chrome-policy.json"), filepath.Join(*out, "chrome-policy.reg")
	if err := writeFileMode(jsonPath, append(policy, '\n'), 0o644); err != nil {
		return err
	}
	if err := writeFileMode(regPath, utf16LE(reg.String()), 0o644); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(a.stdout, "wrote "+jsonPath)
	_, _ = fmt.Fprintln(a.stdout, "wrote "+regPath)
	_, _ = fmt.Fprintln(a.stdout, "Nothing is installed: deploy these files with your device management. They turn off incognito and guest mode.")
	_, _ = fmt.Fprintln(a.stdout, "On Linux copy chrome-policy.json into /etc/opt/chrome/policies/managed (Chrome) and /etc/chromium/policies/managed (Chromium). The .reg file sets both the Chrome and the Chromium keys.")
	return nil
}

// regString quotes a REG_SZ value for a .reg file.
func regString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// utf16LE encodes a .reg file as regedit's version 5 format expects:
// UTF-16LE with a byte-order mark.
func utf16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 0, 2+2*len(units))
	b = append(b, 0xFF, 0xFE)
	for _, u := range units {
		b = binenc.LittleEndian.AppendUint16(b, u)
	}
	return b
}
