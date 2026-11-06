// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M33 range capability (D1216), range setup a live range can provide, named
// with `pclaw redteam run --provides`:
//   - browser_agent: the range has hook connections for the roles pc-browser (pc.browser)
//     and pc-computer (pc.computer) on its gateway, the range run's grant
//     names every pc.browser and pc.computer operation, and its browser
//     site list has docs.example.com and shop.example.com with its
//     subdomains, marked for the cloaking compare (RT-220..RT-224).
func init() {
	capabilities = append(capabilities, "browser_agent")
	CustomerCapabilities = append(CustomerCapabilities, "browser_agent")
}
