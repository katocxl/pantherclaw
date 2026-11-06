// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato
// @ts-check

// Secret and challenge fields (G0 M33 D981, HR-752). A classic content
// script, loaded before content.js in every frame, that sets
// globalThis.pcFields. An agent never types into or submits a password,
// one-time-code or payment field, and never touches a challenge frame
// (FQ33-4): typing, pasting and dropping into such a field is refused, a
// value that still arrives is cleared, and every pointer, key and input
// event in a challenge frame is refused. There is no override; a person
// does that step in a takeover (D982), the only time this is lifted.
// A text area or contenteditable is secret by its name, id, autocomplete or
// aria-label, and a field once seen as secret stays secret (a show-password
// button does not lift it). Cooperative (PARTIAL, R-78): script that sets a
// value directly, input from outside the page's events, and inputs inside a
// closed shadow root are not seen.

(() => {
  /** autocomplete tokens that mark a secret field. */
  const SECRET_AUTOCOMPLETE = new Set([
    "current-password", "new-password", "one-time-code", "cc-name", "cc-given-name", "cc-additional-name",
    "cc-family-name", "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc", "cc-type",
  ]);
  /** name, id, aria-label or placeholder text that marks a secret field. */
  const SECRET_TEXT =
    /(pass(word|wd|code)?|\bpin\b|otp|one.?time|cvv|cvc|csc|security.?code|card.?(number|no|num)|\bcc.?num|iban|routing.?number|account.?number|\bssn\b)/i;
  /** Payment hosts: every input in a frame on one of them is secret. "*." also covers the name itself. */
  const PAYMENT_HOSTS = [
    "js.stripe.com", "checkout.stripe.com", "*.braintreegateway.com", "*.adyen.com", "*.paypal.com", "pay.google.com",
  ];
  /** Challenge hosts: every pointer, key and input event in their frames is refused. */
  const CHALLENGE_HOSTS = [
    "www.recaptcha.net", "*.hcaptcha.com", "challenges.cloudflare.com", "*.arkoselabs.com", "*.funcaptcha.com",
  ];
  const NOTICE =
    "PantherClaw refuses agent input into password, one-time-code, payment and challenge fields. " +
    "A person can take over this tab from the PantherClaw toolbar button.";

  /**
   * @param {string} host
   * @param {string[]} list
   */
  function hostIn(host, list) {
    return list.some((entry) => {
      const base = entry.startsWith("*.") ? entry.slice(2) : entry;
      return host === base || (entry.startsWith("*.") && host.endsWith("." + base));
    });
  }

  /** @type {string[]} extra payment-like hosts from the managed configuration (it can only add). */
  let extraHosts = [];
  let lifted = false;

  function secretFrame() {
    return hostIn(location.hostname, PAYMENT_HOSTS) || hostIn(location.hostname, extraHosts) || challengeFrame();
  }

  function challengeFrame() {
    const host = location.hostname;
    return (host === "www.google.com" && location.pathname.startsWith("/recaptcha/")) || hostIn(host, CHALLENGE_HOSTS);
  }

  /**
   * Fields once seen as secret stay secret: a show-password button changes
   * the type, not the field.
   * @type {WeakSet<HTMLElement>}
   */
  const seenSecret = new WeakSet();

  /**
   * The field el edits: an input, a text area, or the outermost editable
   * host of an element or text node inside contenteditable; otherwise null.
   * @param {EventTarget | null} el
   * @returns {HTMLElement | null}
   */
  function editable(el) {
    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
      return el;
    }
    const node = el instanceof Text ? el.parentElement : el;
    if (!(node instanceof HTMLElement) || !node.isContentEditable) {
      return null;
    }
    let editHost = node;
    while (editHost.parentElement && editHost.parentElement.isContentEditable) {
      editHost = editHost.parentElement;
    }
    return editHost;
  }

  /**
   * Whether el is a secret field: an input, a text area or a contenteditable.
   * @param {EventTarget | null} el
   */
  function isSecret(el) {
    const field = editable(el);
    if (!field) {
      return false;
    }
    if (seenSecret.has(field)) {
      return true;
    }
    if (secretNow(field)) {
      seenSecret.add(field);
      return true;
    }
    return false;
  }

  /** @param {HTMLElement} el */
  function secretNow(el) {
    if (secretFrame() || (el instanceof HTMLInputElement && el.type === "password")) {
      return true;
    }
    const tokens = (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/)
      .filter((t) => t && !t.startsWith("section-") && t !== "shipping" && t !== "billing");
    if (tokens.some((t) => SECRET_AUTOCOMPLETE.has(t))) {
      return true;
    }
    const texts = el instanceof HTMLInputElement
      ? [el.name, el.id, el.getAttribute("aria-label"), el.getAttribute("placeholder")]
      : [el.getAttribute("name"), el.id, el.getAttribute("aria-label")];
    for (const text of texts) {
      if (text && SECRET_TEXT.test(text)) {
        return true;
      }
    }
    return false;
  }

  // An input whose type leaves "password" stays secret, seen or not.
  new MutationObserver((records) => {
    for (const r of records) {
      if (r.target instanceof HTMLInputElement && (r.oldValue || "").toLowerCase() === "password") {
        seenSecret.add(r.target);
      }
    }
  }).observe(document, { subtree: true, attributes: true, attributeFilter: ["type"], attributeOldValue: true });

  /**
   * Whether a form holds a secret input with a value.
   * @param {HTMLFormElement} form
   */
  function formHasSecretValue(form) {
    return Array.from(form.elements).some((el) => isSecret(el) && /** @type {HTMLInputElement} */ (el).value !== "");
  }

  /** @param {Event} e */
  function targetOf(e) {
    const path = e.composedPath();
    return path.length > 0 ? path[0] : e.target;
  }

  /** @type {HTMLElement | null} */
  let banner = null;

  /** Shows a text-only notice in a shadow root at the top of the frame. @param {string} text */
  function showBanner(text) {
    const root = document.documentElement;
    if (!root) {
      return;
    }
    if (!banner) {
      banner = document.createElement("pantherclaw-notice");
      const shadow = banner.attachShadow({ mode: "closed" });
      const box = document.createElement("div");
      box.setAttribute("role", "status");
      box.style.cssText =
        "position:fixed;top:0;left:0;right:0;z-index:2147483647;padding:6px 12px;font:13px/1.4 system-ui,sans-serif;" +
        "background:#1f2933;color:#f5f7fa;border-bottom:2px solid #f0b429;";
      shadow.append(box);
      /** @type {any} */ (banner).pcBox = box;
    }
    /** @type {any} */ (banner).pcBox.textContent = text;
    if (!banner.isConnected) {
      root.append(banner);
    }
  }

  function hideBanner() {
    banner?.remove();
  }

  /** @param {Event} e */
  function refuse(e) {
    e.preventDefault();
    e.stopImmediatePropagation();
    showBanner(NOTICE);
  }

  /** Typing, pasting and dropping into a secret input. @param {Event} e */
  function onEdit(e) {
    if (lifted || !isSecret(targetOf(e))) {
      return;
    }
    if (e instanceof KeyboardEvent && !(e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey)) {
      return; // Tab, arrows and shortcuts still move the focus
    }
    refuse(e);
  }

  /** A value that still arrived is cleared. @param {Event} e */
  function onValue(e) {
    const el = editable(targetOf(e));
    if (lifted || !isSecret(el)) {
      return;
    }
    if (!(el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement)) {
      const editHost = /** @type {HTMLElement} */ (el);
      if (editHost.textContent !== "") {
        editHost.textContent = "";
        showBanner(NOTICE);
      }
      return;
    }
    const input = el;
    if (input.value !== "") {
      input.value = "";
      showBanner(NOTICE);
    }
  }

  /** Every pointer, key and input event in a challenge frame (T1696.001). @param {Event} e */
  function onChallenge(e) {
    if (!lifted && challengeFrame()) {
      refuse(e);
    }
  }

  /** @param {Event} e */
  function onFocus(e) {
    if (!lifted && isSecret(targetOf(e))) {
      showBanner(NOTICE);
    }
  }

  const opts = { capture: true };
  for (const type of ["beforeinput", "paste", "drop", "keydown"]) {
    window.addEventListener(type, onEdit, opts);
  }
  for (const type of ["input", "change"]) {
    window.addEventListener(type, onValue, opts);
  }
  window.addEventListener("focusin", onFocus, opts);
  if (challengeFrame()) {
    for (const type of [
      "pointerdown", "pointerup", "mousedown", "mouseup", "click", "dblclick", "auxclick", "contextmenu",
      "touchstart", "touchend", "keydown", "keyup", "keypress", "beforeinput", "input", "paste", "drop",
    ]) {
      window.addEventListener(type, onChallenge, opts);
    }
  }

  // The managed configuration can only add hosts.
  try {
    chrome.storage.managed.get(["extra_secret_hosts"], (cfg) => {
      const hosts = cfg && Array.isArray(cfg.extra_secret_hosts) ? cfg.extra_secret_hosts : [];
      extraHosts = hosts.filter((h) => typeof h === "string" && h !== "").map((h) => h.toLowerCase());
    });
  } catch {
    // no managed storage: the built-in lists stay
  }

  /** @type {any} */ (globalThis).pcFields = {
    isSecret,
    formHasSecretValue,
    secretFrame,
    challengeFrame,
    showBanner,
    hideBanner,
    notice: NOTICE,
    /** Lifts the refusal during an approved takeover (D982). */
    lift() {
      lifted = true;
    },
    /** Restores it when the takeover ends. */
    restore() {
      lifted = false;
    },
    get lifted() {
      return lifted;
    },
  };
})();
