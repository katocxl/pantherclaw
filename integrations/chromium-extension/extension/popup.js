// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato
// @ts-check

// The toolbar popup (G0 M33 D982): the native host's status, "Take over
// this tab" and "Give back". It refuses to act when opened as a page in a
// tab, so a page or an agent cannot reach the takeover through it.

/** @param {string} id */
function el(id) {
  return /** @type {HTMLElement} */ (document.getElementById(id));
}

/** @param {number} until */
function hhmm(until) {
  const t = new Date(until);
  return String(t.getHours()).padStart(2, "0") + ":" + String(t.getMinutes()).padStart(2, "0");
}

async function main() {
  if (await chrome.tabs.getCurrent()) {
    el("status").textContent = "This page works only as the PantherClaw toolbar popup.";
    return;
  }
  const status = await chrome.runtime.sendMessage({ type: "status" }).catch(() => null);
  el("status").textContent = status && status.ok
    ? "Connected to PantherClaw (connection " + status.connection + ", run " + status.run + ")."
    : "PantherClaw cannot decide: " + ((status && status.reason) || "the native host did not answer.");
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || tab.id === undefined || !/^https?:\/\//.test(tab.url || "")) {
    el("tab").textContent = "Takeover works on http and https tabs only.";
    return;
  }
  const tabId = tab.id;
  const take = /** @type {HTMLButtonElement} */ (el("take"));
  const give = /** @type {HTMLButtonElement} */ (el("give"));

  async function refresh() {
    const s = await chrome.runtime.sendMessage({ type: "tabState", tabId }).catch(() => null);
    const until = Number(s && s.until) || 0;
    take.hidden = until > 0;
    give.hidden = until === 0;
    if (until > 0) {
      el("tab").textContent = "A person is in control of this tab until " + hhmm(until) + ".";
    } else if (s && s.pending) {
      el("tab").textContent = s.pending.held
        ? "PantherClaw holds the takeover for an approval; it asks again every 10 seconds."
        : s.pending.reason || "PantherClaw denied the takeover.";
    } else {
      el("tab").textContent = "";
    }
  }

  take.addEventListener("click", () => {
    take.disabled = true;
    el("tab").textContent = "Asking PantherClaw.";
    void chrome.runtime.sendMessage({ type: "takeover", tabId, page_url: tab.url }).finally(() => {
      take.disabled = false;
      void refresh();
    });
    setTimeout(() => void refresh(), 1000);
  });
  give.addEventListener("click", () => {
    void chrome.runtime.sendMessage({ type: "giveBack", tabId }).finally(() => void refresh());
  });
  await refresh();
}

void main();
