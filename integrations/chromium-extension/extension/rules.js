// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato
// @ts-check

// declarativeNetRequest rules (G0 M33 D980, D982). One dynamic rule sends
// every top-level http(s) navigation to the hold page, where PantherClaw
// decides it; session rules let one decided navigation through on one tab,
// or a whole tab during an approved takeover.

/** The dynamic hold rule's id and priority. */
const HOLD_RULE_ID = 1;
const PRIORITY_NAVIGATION = 2;
const PRIORITY_TAKEOVER = 3;
/** A one-navigation rule that sees no navigation is removed after 60 s. */
const NAVIGATION_RULE_TTL_MS = 60_000;

/** Session rule ids are handed out one at a time. */
let lock = Promise.resolve();

/**
 * Runs fn after every earlier rule change.
 * @template T
 * @param {() => Promise<T>} fn
 * @returns {Promise<T>}
 */
function serial(fn) {
  const next = lock.then(fn, fn);
  lock = next.then(() => undefined, () => undefined);
  return next;
}

/** Escapes a string for an RE2 pattern. @param {string} s */
export function re2Escape(s) {
  return s.replace(/[\\.+*?()|[\]{}^$]/g, "\\$&");
}

/** Installs the hold rule (idempotent; dynamic rules survive restarts). */
export function installHoldRule() {
  return serial(async () => {
    /** @type {chrome.declarativeNetRequest.Rule} */
    const rule = {
      id: HOLD_RULE_ID,
      priority: 1,
      action: {
        type: /** @type {any} */ ("redirect"),
        redirect: { regexSubstitution: `chrome-extension://${chrome.runtime.id}/hold.html#\\0` },
      },
      condition: { regexFilter: "^https?://.*$", resourceTypes: [/** @type {any} */ ("main_frame")] },
    };
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [HOLD_RULE_ID], addRules: [rule] });
  });
}

/** @returns {Promise<number>} an unused session rule id. */
async function nextSessionId() {
  const rules = await chrome.declarativeNetRequest.getSessionRules();
  return rules.reduce((m, r) => Math.max(m, r.id), 1) + 1;
}

/**
 * Lets the next top-level navigation of tabId that matches regex through,
 * once: the rule goes when that tab commits or fails a navigation, or after
 * 60 s.
 * @param {number} tabId
 * @param {string} regex
 */
export function allowNavigationOnce(tabId, regex) {
  return serial(async () => {
    const id = await nextSessionId();
    await chrome.declarativeNetRequest.updateSessionRules({
      addRules: [{
        id,
        priority: PRIORITY_NAVIGATION,
        action: { type: /** @type {any} */ ("allow") },
        condition: { regexFilter: regex, resourceTypes: [/** @type {any} */ ("main_frame")], tabIds: [tabId] },
      }],
    });
    setTimeout(() => void removeRules([id]), NAVIGATION_RULE_TTL_MS);
    return id;
  });
}

/** Removes the one-navigation rules of a tab (not its takeover rule). @param {number} tabId */
export function removeNavigationRules(tabId) {
  return serial(async () => {
    const rules = await chrome.declarativeNetRequest.getSessionRules();
    const ids = rules
      .filter((r) => r.priority === PRIORITY_NAVIGATION && r.condition.tabIds?.includes(tabId))
      .map((r) => r.id);
    if (ids.length > 0) {
      await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids });
    }
  });
}

/** @param {number[]} ids */
function removeRules(ids) {
  return serial(() => chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids }));
}

/** Lets every top-level navigation of tabId through during a takeover. @param {number} tabId */
export function addTakeoverRule(tabId) {
  return serial(async () => {
    const id = await nextSessionId();
    await chrome.declarativeNetRequest.updateSessionRules({
      addRules: [{
        id,
        priority: PRIORITY_TAKEOVER,
        action: { type: /** @type {any} */ ("allow") },
        condition: { resourceTypes: [/** @type {any} */ ("main_frame")], tabIds: [tabId] },
      }],
    });
    return id;
  });
}

/** Removes a tab's takeover rule. @param {number} tabId */
export function removeTakeoverRule(tabId) {
  return serial(async () => {
    const rules = await chrome.declarativeNetRequest.getSessionRules();
    const ids = rules
      .filter((r) => r.priority === PRIORITY_TAKEOVER && r.condition.tabIds?.includes(tabId))
      .map((r) => r.id);
    if (ids.length > 0) {
      await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids });
    }
  });
}
