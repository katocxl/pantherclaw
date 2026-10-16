// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// Automation endpoint pages (G0 M11 part 2 D20–D22, D53; HR-275).
// Activating or rotating an inbound event source or an automation
// destination, and starting a version that requires it, first step up
// with a security key (WebAuthn, user verification), then send a
// same-origin JSON request with the PC-CSRF header (HR-151). The page runs
// under Trusted Types: text is written with textContent only, and every
// action's path comes from the server-rendered page, never the URL.
"use strict";

class APIError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

async function post(path, body) {
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "PC-CSRF": "1" },
    body: JSON.stringify(body || {}),
  });
  let data = {};
  try { data = await res.json(); } catch (e) { data = {}; }
  if (!res.ok) { throw new APIError(data.error || ("http_" + res.status)); }
  return data;
}

function say(text) {
  const el = document.getElementById("status");
  if (el) { el.textContent = text; }
}

const messages = {
  no_keys: "You need a security key on your account first (add one on your account page).",
  step_up_required: "Verify with your security key first.",
  verification_failed: "The security key's answer could not be verified.",
  forbidden: "You cannot do this: it needs the permission and a person's session.",
  edition: "Automations need the Team edition or above.",
  not_found: "It does not exist, or you cannot see it.",
  not_pending: "It is no longer in a state that allows this. Reload the page.",
  rotating: "The previous secret is still in its 24-hour overlap; rotate again once it ends.",
  url_refused: "The destination's URL is no longer allowed. Create a new destination.",
  not_manual: "This automation's enabled version is not started by hand.",
  invalid: "Check the values and the idempotency key.",
};

function explain(e) { return messages[e.code] || ("Something went wrong (" + e.message + ")."); }

function fromB64(s) {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) { out[i] = b.charCodeAt(i); }
  return out.buffer;
}

function toB64(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (const x of bytes) { s += String.fromCharCode(x); }
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function requestOptions(o) {
  if (window.PublicKeyCredential && PublicKeyCredential.parseRequestOptionsFromJSON) {
    return PublicKeyCredential.parseRequestOptionsFromJSON(o);
  }
  const p = Object.assign({}, o);
  p.challenge = fromB64(o.challenge);
  p.allowCredentials = (o.allowCredentials || []).map((c) => Object.assign({}, c, { id: fromB64(c.id) }));
  return p;
}

function credentialJSON(c) {
  if (typeof c.toJSON === "function") { return c.toJSON(); }
  const r = c.response;
  const out = { id: c.id, rawId: toB64(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults(), response: {} };
  out.response.clientDataJSON = toB64(r.clientDataJSON);
  out.response.authenticatorData = toB64(r.authenticatorData);
  out.response.signature = toB64(r.signature);
  if (r.userHandle) { out.response.userHandle = toB64(r.userHandle); }
  return out;
}

// stepUp proves possession of a security key on this browser session
// (the account page's step-up, M5 part 1).
async function stepUp() {
  const c = await post("/account/step-up-options");
  const cred = await navigator.credentials.get({ publicKey: requestOptions(c.options.publicKey) });
  await post("/account/step-up", { ceremony: c.ceremony, response: credentialJSON(cred) });
}

async function act(button) {
  try {
    say("Waiting for your security key…");
    await stepUp();
    const data = await post(button.dataset.path, {});
    if (data.signing_secret) {
      say("Rotated. The new secret is shown below once; store it now.");
      const el = document.getElementById("secret");
      if (el) { el.textContent = data.signing_secret; }
      return;
    }
    say("Done.");
    window.location.reload();
  } catch (e) {
    say(e instanceof APIError ? explain(e) : "The security key did not answer (" + e.message + ").");
  }
}

for (const b of document.querySelectorAll("button[data-action]")) {
  b.addEventListener("click", () => act(b));
}

const form = document.getElementById("start-form");
if (form) {
  const key = document.getElementById("idempotency-key");
  if (key && !key.value && window.crypto && crypto.randomUUID) { key.value = crypto.randomUUID(); }
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const params = {};
    for (const el of form.querySelectorAll("input[name], select[name]")) {
      if (el.name !== "idempotency_key" && el.value !== "") { params[el.name] = el.value; }
    }
    try {
      if (form.dataset.stepUp === "true") {
        say("Waiting for your security key…");
        await stepUp();
      }
      const data = await post(form.dataset.path, { params: params, idempotency_key: key ? key.value : "" });
      say("Trigger " + data.trigger + ": " + data.state + (data.reason ? " (" + data.reason + ")" : "") +
        (data.execution ? "; execution " + data.execution : "") + ".");
    } catch (e) {
      say(e instanceof APIError ? explain(e) : "The security key did not answer (" + e.message + ").");
    }
  });
}
