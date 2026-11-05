// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato
// @ts-check

// The extension's service worker (G0 M33 D980, D982). It asks PantherClaw,
// through the native host, before the agent's browser opens a page, submits
// a form, saves a download or clicks an element an admin marked, and it
// runs the takeover. Without an answer nothing happens: navigations stay on
// the hold page, downloads are cancelled, and submits and marked clicks
// stay blocked (fail closed, HR-751). Only the D974 inputs leave the
// browser: no screenshot, DOM, field value or page text (HR-754).
// Cooperative (PARTIAL, R-78).

import { Host, cannotDecide } from "./host.js";
import {
  addTakeoverRule, allowNavigationOnce, installHoldRule, re2Escape, removeNavigationRules, removeTakeoverRule,
} from "./rules.js";

/** @typedef {import("./host.js").Answer} Answer */

const DEFAULT_HOST_NAME = "dev.pantherclaw.browser";
const MAX_URL = 1800;
const TAKEOVER_MINUTES = 10;
const TAKEOVER_RETRY_MS = 10_000;
const TAKEOVER_WAIT_MS = 15 * 60_000;

async function hostName() {
  try {
    const cfg = await chrome.storage.managed.get(["host_name"]);
    if (typeof cfg.host_name === "string" && /^[a-z0-9_]+(\.[a-z0-9_]+)*$/.test(cfg.host_name)) {
      return cfg.host_name;
    }
  } catch {
    // no managed storage
  }
  return DEFAULT_HOST_NAME;
}

const host = new Host(hostName);

/** A new call id, as the pc.browser mapping accepts it. */
function newCall() {
  return "pc-" + crypto.randomUUID();
}

// ---- takeover state (D982) ----

/** @param {number} tabId */
function takeoverKey(tabId) {
  return "takeover:" + tabId;
}

/**
 * The end of a tab's approved takeover (ms), or 0. A takeover past its end
 * is ended here: it is checked at every event.
 * @param {number | undefined} tabId
 */
async function takeoverUntil(tabId) {
  if (tabId === undefined || tabId < 0) {
    return 0;
  }
  const key = takeoverKey(tabId);
  const got = await chrome.storage.session.get(key);
  const until = Number(got[key] || 0);
  if (until === 0) {
    return 0;
  }
  if (until <= Date.now()) {
    await endTakeover(tabId);
    return 0;
  }
  return until;
}

/** @param {number} tabId @param {number} until */
async function startTakeover(tabId, until) {
  await chrome.storage.session.set({ [takeoverKey(tabId)]: until });
  await addTakeoverRule(tabId);
  await chrome.alarms.create(takeoverKey(tabId), { when: until });
  notifyTab(tabId, until);
}

/** @param {number} tabId */
async function endTakeover(tabId) {
  await chrome.storage.session.remove(takeoverKey(tabId));
  await removeTakeoverRule(tabId);
  await chrome.alarms.clear(takeoverKey(tabId));
  notifyTab(tabId, 0);
}

/** Tells every frame of a tab whether it is in a takeover. @param {number} tabId @param {number} until */
function notifyTab(tabId, until) {
  chrome.tabs.sendMessage(tabId, { type: "takeover", until }).catch(() => undefined);
}

/** Pending takeover requests, by tab: the popup's "Take over" asks again while held. */
/** @type {Map<number, {answer: Answer, started: number}>} */
const takeoverRequests = new Map();

/**
 * Asks browser_takeover for a tab; while held, asks again every 10 s for up
 * to 15 min (same call and action id).
 * @param {number} tabId
 * @param {string} pageUrl
 */
async function requestTakeover(tabId, pageUrl) {
  if (takeoverRequests.has(tabId)) {
    return takeoverRequests.get(tabId)?.answer;
  }
  const input = { page_url: pageUrl, minutes: TAKEOVER_MINUTES, call: newCall() };
  const actionId = crypto.randomUUID();
  const started = Date.now();
  takeoverRequests.set(tabId, { answer: { ...cannotDecide(), held: true, reason: "Asking PantherClaw." }, started });
  for (;;) {
    const answer = await host.decide("browser_takeover", input, actionId);
    takeoverRequests.set(tabId, { answer, started });
    if (answer.decision === "allow") {
      takeoverRequests.delete(tabId);
      await startTakeover(tabId, Date.now() + TAKEOVER_MINUTES * 60_000);
      return answer;
    }
    if (!answer.held || Date.now() - started + TAKEOVER_RETRY_MS > TAKEOVER_WAIT_MS) {
      setTimeout(() => takeoverRequests.delete(tabId), TAKEOVER_RETRY_MS);
      return answer;
    }
    await new Promise((r) => setTimeout(r, TAKEOVER_RETRY_MS));
  }
}

// ---- decisions ----

/** @type {Answer} */
const LOCAL_TAKEOVER = { decision: "allow", held: false, code: "", reason: "A person is in control of this tab.", transaction_id: "" };

/**
 * Decides a navigation the hold page asks about; on allow, lets it through
 * once on that tab.
 * @param {number} tabId
 * @param {any} m
 * @returns {Promise<Answer>}
 */
async function decideNavigate(tabId, m) {
  const url = String(m.url || "");
  if (!/^https?:\/\//.test(url)) {
    return cannotDecide("PantherClaw decides http and https pages only.");
  }
  if (url.length > MAX_URL) {
    return { ...cannotDecide("The address is too long for PantherClaw to decide, so it is blocked."), code: "BROWSER_URL_TOO_LONG" };
  }
  const input = {
    url, user_agent: String(m.user_agent || ""), accept_language: String(m.accept_language || ""), call: String(m.call || ""),
  };
  const answer = await host.decide("browser_navigate", input, String(m.action_id || ""));
  if (answer.decision === "allow") {
    await allowNavigationOnce(tabId, "^" + re2Escape(url) + "$");
  }
  return answer;
}

/**
 * Decides a form submit. A submit with a secret field stays blocked
 * whatever the answer (D981); the question is still asked so the gateway
 * records the refusal.
 * @param {number} tabId
 * @param {any} m
 * @returns {Promise<Answer>}
 */
async function decideSubmit(tabId, m) {
  const fields = Array.isArray(m.fields) ? m.fields.filter((f) => typeof f === "string").slice(0, 64) : [];
  const input = {
    url: String(m.url || ""), page_url: String(m.page_url || ""), method: m.method === "get" ? "get" : "post",
    fields, secret_fields: m.secret_fields === true, call: newCall(),
  };
  const answer = await host.decide("browser_submit", input, crypto.randomUUID());
  if (input.secret_fields) {
    return { ...answer, decision: "deny" };
  }
  if (answer.decision === "allow") {
    const action = input.url.split("?")[0];
    await allowNavigationOnce(tabId, "^" + re2Escape(action) + "(\\?.*)?$");
  }
  return answer;
}

/**
 * Decides a click on an element an admin marked.
 * @param {any} m
 * @returns {Promise<Answer>}
 */
function decideClick(m) {
  const input = {
    page_url: String(m.page_url || ""), selector: String(m.selector || "").slice(0, 256),
    label: String(m.label || "").trim().slice(0, 128), call: newCall(),
  };
  return host.decide("browser_click", input, crypto.randomUUID());
}

/**
 * Whether a download comes from a tab in a takeover: its referrer is that
 * tab's page (a download names no tab).
 * @param {chrome.downloads.DownloadItem} item
 */
async function fromTakeoverTab(item) {
  const all = await chrome.storage.session.get(null);
  for (const key of Object.keys(all)) {
    if (!key.startsWith("takeover:")) {
      continue;
    }
    const tabId = Number(key.slice("takeover:".length));
    if ((await takeoverUntil(tabId)) === 0) {
      continue;
    }
    const tab = await chrome.tabs.get(tabId).catch(() => null);
    if (tab && item.referrer && tab.url === item.referrer) {
      return true;
    }
  }
  return false;
}

/** Pauses every download at once and saves it only on allow. @param {chrome.downloads.DownloadItem} item */
async function onDownload(item) {
  try {
    await chrome.downloads.pause(item.id);
  } catch {
    // already complete or interrupted: decided below all the same
  }
  if (await fromTakeoverTab(item)) {
    await chrome.downloads.resume(item.id).catch(() => undefined);
    return;
  }
  /** @type {Record<string, unknown>} */
  const input = {
    url: item.finalUrl || item.url, page_url: item.referrer || "", filename: baseName(item.filename).slice(0, 255),
    mime: String(item.mime || "").slice(0, 127), call: newCall(),
  };
  if (typeof item.totalBytes === "number" && item.totalBytes >= 0) {
    input.bytes = item.totalBytes;
  }
  const answer = await host.decide("browser_download", input, crypto.randomUUID());
  if (answer.decision === "allow") {
    await chrome.downloads.resume(item.id).catch(() => undefined);
    return;
  }
  await chrome.downloads.cancel(item.id).catch(() => undefined);
  const [now] = await chrome.downloads.search({ id: item.id }).catch(() => []);
  if (now && now.state === "complete") {
    await chrome.downloads.removeFile(item.id).catch(() => undefined);
  }
  await chrome.downloads.erase({ id: item.id }).catch(() => undefined);
}

/** @param {string} path */
function baseName(path) {
  return String(path || "").split(/[\\/]/).pop() || "";
}

// ---- messages from the hold page, the content scripts and the popup ----

chrome.runtime.onMessage.addListener((m, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !m || typeof m.type !== "string") {
    return false;
  }
  const tabId = sender.tab?.id;
  if ((m.type === "takeover" || m.type === "giveBack" || m.type === "tabState") && sender.tab) {
    // Only the toolbar popup runs a takeover, never a page or a tab (D982).
    return false;
  }
  /** @type {Promise<unknown>} */
  let reply;
  switch (m.type) {
    case "navigate":
    case "submit":
    case "click":
      if (tabId === undefined) {
        reply = Promise.resolve(cannotDecide());
        break;
      }
      reply = takeoverUntil(tabId).then((until) => {
        if (until > 0) {
          return LOCAL_TAKEOVER; // nothing on this tab is decided or recorded until it ends (R-79)
        }
        if (m.type === "navigate") {
          return decideNavigate(tabId, m);
        }
        return m.type === "submit" ? decideSubmit(tabId, m) : decideClick(m);
      });
      break;
    case "state":
      reply = takeoverUntil(tabId).then((until) => ({ until }));
      break;
    case "status":
      reply = host.status();
      break;
    case "tabState":
      reply = takeoverUntil(Number(m.tabId)).then((until) => ({
        until, pending: takeoverRequests.get(Number(m.tabId))?.answer || null,
      }));
      break;
    case "takeover":
      reply = requestTakeover(Number(m.tabId), String(m.page_url || ""));
      break;
    case "giveBack":
      reply = endTakeover(Number(m.tabId)).then(() => ({ until: 0 }));
      break;
    default:
      return false;
  }
  reply.then(sendResponse, () => sendResponse(cannotDecide()));
  return true;
});

chrome.downloads.onCreated.addListener((item) => void onDownload(item));

/** A tab's one-navigation rules go once it commits or fails a navigation. */
chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId === 0) {
    void removeNavigationRules(d.tabId);
    void takeoverUntil(d.tabId);
  }
});
chrome.webNavigation.onErrorOccurred.addListener((d) => {
  if (d.frameId === 0) {
    void removeNavigationRules(d.tabId);
  }
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name.startsWith("takeover:")) {
    void endTakeover(Number(alarm.name.slice("takeover:".length)));
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  void endTakeover(tabId);
  void removeNavigationRules(tabId);
});

chrome.runtime.onInstalled.addListener(() => void installHoldRule());
chrome.runtime.onStartup.addListener(() => void installHoldRule());
void installHoldRule();
void host.connect();
