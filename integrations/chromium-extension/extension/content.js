// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato
// @ts-check

// The content script (G0 M33 D980, D982), after fields.js in every frame.
// It holds every form submit and every click on an element an admin marked
// until PantherClaw allows it, and it shows and lifts the takeover. Without
// an answer the submit or the click does not happen (fail closed, HR-751).
// It sends only the D974 inputs: field names, never values (HR-754).
// Cooperative (PARTIAL, R-78): a scripted form.submit() fires no submit
// event (the navigation rule still holds its navigation), and fetch/XHR
// from page scripts is not seen.

(() => {
  /** @type {any} */
  const pcFields = /** @type {any} */ (globalThis).pcFields;
  const FIELD_NAME = /^[A-Za-z0-9_.:[\]-]{1,64}$/;
  const MAX_FIELDS = 64;

  /** @type {WeakSet<object>} submits and clicks allowed once */
  const oneShot = new WeakSet();
  /** @type {{host: string, include_subdomains: boolean, selectors: string[]}[]} */
  let clickRules = [];
  let takeoverUntil = 0;
  /** @type {ReturnType<typeof setTimeout> | null} */
  let takeoverTimer = null;

  function inTakeover() {
    return takeoverUntil > Date.now();
  }

  /**
   * Asks the service worker; anything but an allow is a deny.
   * @param {Record<string, unknown>} msg
   * @returns {Promise<{decision: string, reason?: string}>}
   */
  async function ask(msg) {
    try {
      const a = await chrome.runtime.sendMessage(msg);
      return a && typeof a.decision === "string" ? a : { decision: "deny" };
    } catch {
      return { decision: "deny" };
    }
  }

  // ---- form submits ----

  /**
   * @param {HTMLFormElement} form
   * @param {HTMLElement | null} submitter
   */
  function describeSubmit(form, submitter) {
    const btn = /** @type {HTMLButtonElement | HTMLInputElement | null} */ (submitter);
    const action = (btn && btn.hasAttribute("formaction") ? btn.formAction : form.action) || location.href;
    const method = ((btn && btn.hasAttribute("formmethod") ? btn.formMethod : form.method) || "get").toLowerCase();
    /** @type {string[]} */
    const fields = [];
    for (const el of Array.from(form.elements)) {
      const name = /** @type {HTMLInputElement} */ (el).name;
      if (name && FIELD_NAME.test(name) && !fields.includes(name) && fields.length < MAX_FIELDS) {
        fields.push(name);
      }
    }
    return { url: action, page_url: location.href, method, fields, secret_fields: pcFields.formHasSecretValue(form) };
  }

  window.addEventListener("submit", (e) => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement) || inTakeover()) {
      return;
    }
    if (oneShot.has(form)) {
      oneShot.delete(form);
      return;
    }
    const submitter = /** @type {SubmitEvent} */ (e).submitter || null;
    const info = describeSubmit(form, submitter);
    if (info.method === "dialog") {
      return; // closes a dialog; nothing leaves the page
    }
    e.preventDefault();
    e.stopImmediatePropagation();
    if (info.secret_fields) {
      // Refused locally and still asked, so the gateway records the refusal (D981).
      pcFields.showBanner(pcFields.notice);
    }
    void ask({ type: "submit", ...info }).then((a) => {
      if (a.decision !== "allow" || info.secret_fields || !form.isConnected) {
        return;
      }
      oneShot.add(form);
      form.requestSubmit(submitter && form.contains(submitter) ? submitter : undefined);
    });
  }, { capture: true });

  // ---- marked clicks ----

  /** @param {string} host @param {{host: string, include_subdomains: boolean}} rule */
  function ruleMatches(host, rule) {
    const h = String(rule.host || "").toLowerCase();
    return h !== "" && (host === h || (rule.include_subdomains === true && host.endsWith("." + h)));
  }

  /** @param {Element} el */
  function labelOf(el) {
    const aria = el.getAttribute("aria-label");
    const text = aria || /** @type {HTMLElement} */ (el).innerText || el.textContent || "";
    return text.trim().slice(0, 128);
  }

  /** @param {MouseEvent} e */
  function onClick(e) {
    if (inTakeover() || clickRules.length === 0) {
      return;
    }
    const target = e.composedPath()[0];
    if (!(target instanceof Element)) {
      return;
    }
    const host = location.hostname;
    for (const rule of clickRules) {
      if (!ruleMatches(host, rule)) {
        continue;
      }
      for (const selector of rule.selectors || []) {
        let el = null;
        try {
          el = target.closest(selector);
        } catch {
          continue; // not a valid selector
        }
        if (!el) {
          continue;
        }
        if (oneShot.has(el)) {
          oneShot.delete(el);
          return;
        }
        e.preventDefault();
        e.stopImmediatePropagation();
        const marked = /** @type {HTMLElement} */ (el);
        void ask({ type: "click", page_url: location.href, selector, label: labelOf(marked) }).then((a) => {
          if (a.decision === "allow" && marked.isConnected) {
            oneShot.add(marked);
            marked.click();
          }
        });
        return;
      }
    }
  }
  window.addEventListener("click", onClick, { capture: true });
  window.addEventListener("auxclick", onClick, { capture: true });

  try {
    chrome.storage.managed.get(["click_rules"], (cfg) => {
      const rules = cfg && Array.isArray(cfg.click_rules) ? cfg.click_rules : [];
      clickRules = rules.filter((r) => r && typeof r.host === "string" && Array.isArray(r.selectors))
        .map((r) => ({
          host: r.host, include_subdomains: r.include_subdomains === true,
          selectors: r.selectors.filter((s) => typeof s === "string" && s.length > 0 && s.length <= 256),
        }));
    });
  } catch {
    // no managed storage: no marked clicks
  }

  // ---- takeover (D982) ----

  /** @param {number} until */
  function applyTakeover(until) {
    takeoverUntil = until;
    if (takeoverTimer) {
      clearTimeout(takeoverTimer);
      takeoverTimer = null;
    }
    if (inTakeover()) {
      pcFields.lift();
      if (window === window.top) {
        const t = new Date(until);
        const hhmm = String(t.getHours()).padStart(2, "0") + ":" + String(t.getMinutes()).padStart(2, "0");
        pcFields.showBanner("A person is in control of this tab until " + hhmm);
      }
      takeoverTimer = setTimeout(() => applyTakeover(0), until - Date.now());
    } else {
      pcFields.restore();
      pcFields.hideBanner();
    }
  }

  chrome.runtime.onMessage.addListener((m, sender) => {
    if (sender.id === chrome.runtime.id && m && m.type === "takeover") {
      applyTakeover(Number(m.until) || 0);
    }
    return false;
  });

  void chrome.runtime.sendMessage({ type: "state" }).then((s) => applyTakeover(Number(s && s.until) || 0), () => undefined);
})();
