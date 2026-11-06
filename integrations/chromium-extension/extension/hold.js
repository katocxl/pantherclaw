// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato
// @ts-check

// The hold page (G0 M33 D980). Every top-level http(s) navigation of the
// agent's browser lands here first, with the address in the fragment. It
// asks browser_navigate and opens the page only on allow. While the answer
// is a hold it asks again every 10 s for up to 30 min with the same call
// and action id; anything else leaves the page here (fail closed, HR-751).

const RETRY_MS = 10_000;
const WAIT_MS = 30 * 60_000;
const MAX_URL = 1800;

/** @param {string} title @param {string} detail */
function show(title, detail) {
  const t = document.getElementById("title");
  const d = document.getElementById("detail");
  if (t) t.textContent = title;
  if (d) d.textContent = detail;
}

async function main() {
  const url = location.hash.slice(1);
  const target = document.getElementById("url");
  if (target) target.textContent = url;
  if (!/^https?:\/\//.test(url)) {
    show("PantherClaw cannot decide", "This is not an http or https address.");
    return;
  }
  if (url.length > MAX_URL) {
    show("PantherClaw refused this page", "The address is too long for PantherClaw to decide (BROWSER_URL_TOO_LONG).");
    return;
  }
  const tab = await chrome.tabs.getCurrent();
  if (!tab || tab.id === undefined) {
    show("PantherClaw cannot decide", "This page only works in a tab.");
    return;
  }
  // The call and action id stay the same while the navigation is held.
  const key = "nav:" + tab.id + ":" + url;
  const saved = (await chrome.storage.session.get(key))[key];
  const ids = saved && typeof saved.call === "string" && typeof saved.action_id === "string"
    ? saved
    : { call: "pc-" + crypto.randomUUID(), action_id: crypto.randomUUID() };
  await chrome.storage.session.set({ [key]: ids });
  const started = Date.now();
  for (;;) {
    show("Asking PantherClaw", "PantherClaw decides whether the agent's browser opens this page.");
    /** @type {any} */
    let a = null;
    try {
      a = await chrome.runtime.sendMessage({
        type: "navigate", url, user_agent: navigator.userAgent, accept_language: navigator.language, ...ids,
      });
    } catch {
      a = null;
    }
    if (a && a.decision === "allow") {
      await chrome.storage.session.remove(key);
      location.replace(url);
      return;
    }
    if (a && a.held && Date.now() - started + RETRY_MS <= WAIT_MS) {
      show("PantherClaw holds this page", (a.reason || "It waits for a person in PantherClaw.") + " This page asks again every 10 seconds.");
      await new Promise((r) => setTimeout(r, RETRY_MS));
      continue;
    }
    await chrome.storage.session.remove(key);
    if (!a || a.code === "CANNOT_DECIDE") {
      show("PantherClaw cannot decide", (a && a.reason) || "The PantherClaw native host did not answer, so the page stays closed.");
    } else {
      show("PantherClaw refused this page", a.reason || "PantherClaw denied this navigation.");
    }
    return;
  }
}

void main();
