// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// MCP consent page (G0 M26 D408.4). The answer is a same-origin JSON
// request with the PC-CSRF header (HR-151); its path and the request it
// answers come from the server-rendered page, and the server says where to
// send the browser next. Text is written with textContent only.
"use strict";
for (const [id, approve] of [["mcp-allow", true], ["mcp-deny", false]]) {
  const button = document.getElementById(id);
  if (!button) { continue; }
  button.addEventListener("click", async () => {
    for (const b of document.querySelectorAll("button")) { b.disabled = true; }
    const status = document.getElementById("status");
    try {
      const res = await fetch(button.dataset.path, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "PC-CSRF": "1" },
        body: JSON.stringify({ query: button.dataset.query, approve: approve }),
      });
      let data = {};
      try { data = await res.json(); } catch (e) { data = {}; }
      if (!res.ok || !data.next) {
        status.textContent = res.status === 403 ? "Sign in to this organization yourself to answer this request." : "This request can't be answered any more. Start again from the client.";
        return;
      }
      window.location.assign(data.next);
    } catch (e) {
      status.textContent = "Unable to reach the server. Try again.";
      for (const b of document.querySelectorAll("button")) { b.disabled = false; }
    }
  });
}
