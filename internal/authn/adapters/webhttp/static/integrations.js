// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// Integration activation pages (G0 M10 D35, D37; HR-259, HR-261).
// Activating an export destination or a Shared Signals transmitter first
// steps up with a security key (WebAuthn, user verification), then sends a
// same-origin JSON request with the PC-CSRF header (HR-151). The page runs
// under Trusted Types: text is written with textContent only, and the
// action's path comes from the server-rendered button, never the URL.
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
  forbidden: "You cannot activate it: that needs the manage permission and a person's session.",
  not_found: "It does not exist, or you cannot see it.",
  not_pending: "It is no longer waiting for activation. Reload the page.",
  url_refused: "The destination's URL is no longer allowed. Create a new destination.",
  protected_change_pending: "Your organization protects this change: it now waits for a second person.",
  rotation_untested: "The new key has not passed its test at GitHub.",
  rotation_state: "The rotation has moved on. Reload the page.",
  rollback_closed: "The rollback window is closed.",
  rotation_reason: "Give a reason of 1 to 500 characters.",
  invalid_request: "The form could not be read. Reload the page.",
  edition_required: "Your edition does not include this.",
  invalid_export_destination: "Check the name, target and data classes.",
  invalid_export_credential: "Give the credential this kind of destination uses.",
  export_destination_url: "This URL is not allowed.",
  export_destination_metadata: "This URL is not allowed.",
  export_destination_exists: "A destination of that name exists.",
  identity_provider_invalid: "Check the name, issuer URL, client id and client secret.",
  identity_provider_discovery: "The issuer did not answer as an OpenID provider.",
  identity_provider_name_taken: "A provider of that name exists.",
  identity_provider_limit: "This organization has as many providers as it can have.",
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

async function activate(path) {
  try {
    say("Waiting for your security key…");
    await stepUp();
    await post(path, {});
    say("Activated.");
    window.location.reload();
  } catch (e) {
    say(e instanceof APIError ? explain(e) : "The security key did not answer (" + e.message + ").");
  }
}

const activateButton = document.getElementById("activate");
if (activateButton) { activateButton.addEventListener("click", () => activate(activateButton.dataset.path)); }

// rollBack is activate with the person's reason (G0 M22 D5).
async function rollBack(path, reason) {
  try {
    say("Waiting for your security key…");
    await stepUp();
    await post(path, { reason: reason });
    say("Rolled back.");
    window.location.reload();
  } catch (e) {
    say(e instanceof APIError ? explain(e) : "The security key did not answer (" + e.message + ").");
  }
}

const rollbackButton = document.getElementById("rollback");
if (rollbackButton) {
  rollbackButton.addEventListener("click", () => rollBack(rollbackButton.dataset.path, document.getElementById("reason").value));
}
