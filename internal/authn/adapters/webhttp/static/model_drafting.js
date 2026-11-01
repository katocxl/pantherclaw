// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// Model drafting settings page (G0 M21 D309). Turning drafting on or saving
// the key first steps up with a security key (WebAuthn, user verification),
// then sends a same-origin JSON request with the PC-CSRF header (HR-151);
// turning it off and clearing the key send the request alone (D312). The
// page runs under Trusted Types: text is written with textContent only, and
// the action's path comes from the server-rendered button, never the URL.
// The key leaves the input once, in the request body, and the input is
// cleared as soon as it has been sent.
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
  plan_required: "This organization's plan does not allow this. Choose a plan in Settings, Plan and billing.",
  verification_failed: "The security key's answer could not be verified.",
  forbidden: "You cannot change this: that needs org.update and a person's session.",
  edition_required: "Model drafting needs the Business edition.",
  unavailable: "This server does not offer model drafting.",
  no_key: "Save the provider key first.",
  invalid_key: "That is not a valid provider key.",
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

async function change(path, body) {
  try {
    say("Waiting for your security key…");
    await stepUp();
    await post(path, body);
    say("Saved.");
    window.location.reload();
  } catch (e) {
    say(e instanceof APIError ? explain(e) : "The security key did not answer (" + e.message + ").");
  }
}

async function leave(path) {
  try {
    await post(path);
    say("Saved.");
    window.location.reload();
  } catch (e) {
    say(explain(e));
  }
}

for (const id of ["disable", "clear-key"]) {
  const button = document.getElementById(id);
  if (button) { button.addEventListener("click", () => leave(button.dataset.path)); }
}

const enableButton = document.getElementById("enable");
if (enableButton) { enableButton.addEventListener("click", () => change(enableButton.dataset.path, {})); }

const keyButton = document.getElementById("set-key");
if (keyButton) {
  keyButton.addEventListener("click", () => {
    const input = document.getElementById("key");
    const key = input.value;
    input.value = "";
    change(keyButton.dataset.path, { key: key });
  });
}
