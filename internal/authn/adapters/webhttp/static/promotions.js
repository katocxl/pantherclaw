// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// Production promotions page (G0 M11 part 2, D39, D53; HR-290). Promoting
// first steps up with a security key (WebAuthn, user verification), then
// sends a same-origin JSON request with the PC-CSRF header (HR-151). The
// page runs under Trusted Types: text is written with textContent only,
// and the action's path and environment come from the server-rendered
// button, never the URL.
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
  forbidden: "You cannot promote this agent: that needs agent.promote and a person's session.",
  not_found: "The agent does not exist, or you cannot see it.",
  environment_mismatch: "The agent works in another environment.",
  not_production: "Promotions are for production environments only.",
  bad_request: "Choose at least one operation and a failure behavior.",
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

async function promote(button) {
  const operations = Array.from(document.querySelectorAll("input.operation:checked")).map((el) => el.value);
  const behavior = document.getElementById("failure-behavior");
  try {
    say("Waiting for your security key…");
    await stepUp();
    const res = await post(button.dataset.path, {
      environment_id: button.dataset.environment, operations: operations, failure_behavior: behavior ? behavior.value : "",
    });
    say("Promoted: " + (res.promoted.join(", ") || "none") + ". Not ready: " + (res.not_ready.join(", ") || "none") + ".");
    window.setTimeout(() => window.location.reload(), 1500);
  } catch (e) {
    say(e instanceof APIError ? explain(e) : "The security key did not answer (" + e.message + ").");
  }
}

const promoteButton = document.getElementById("promote");
if (promoteButton) { promoteButton.addEventListener("click", () => promote(promoteButton)); }
