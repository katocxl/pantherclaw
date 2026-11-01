// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// Support access and break-glass pages (G0 M13 D32, D33, D38). Asking for
// support access, opening a support session, approving or denying a
// request and activating break-glass first step up with a security key
// (WebAuthn, user verification), then send a same-origin JSON request
// with the PC-CSRF header (HR-151). The page runs under Trusted Types:
// text is written with textContent only, and every action's path comes
// from the server-rendered page, never the URL; a "next" the server
// returns is followed only when it is a same-origin path.
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
  forbidden: "You cannot do this.",
  self_approval: "Nobody can decide their own support request.",
  edition: "This needs a higher edition for the organization.",
  unavailable: "Support access is not available on this server.",
  invalid: "Check the values: a task of 1 to 200 characters, a scope and 1 to 72 hours.",
  not_found: "It does not exist, or you cannot see it.",
  not_pending: "It is no longer pending. Reload the page.",
  no_grant: "There is no approved grant in force for this request.",
  not_holder: "You are not a break-glass holder.",
  active: "Your break-glass access is already active.",
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

// stepUp proves possession of a security key on this browser session.
async function stepUp() {
  const c = await post("/account/step-up-options");
  const cred = await navigator.credentials.get({ publicKey: requestOptions(c.options.publicKey) });
  await post("/account/step-up", { ceremony: c.ceremony, response: credentialJSON(cred) });
}

function follow(next) {
  if (typeof next === "string" && next.startsWith("/") && !next.startsWith("//") && next.indexOf("\\") < 0) {
    window.location.assign(next);
    return true;
  }
  return false;
}

async function run(path, body) {
  try {
    say("Waiting for your security key…");
    await stepUp();
    const data = await post(path, body);
    say("Done.");
    if (!follow(data.next)) { window.location.reload(); }
  } catch (e) {
    say(e instanceof APIError ? explain(e) : "The security key did not answer (" + e.message + ").");
  }
}

for (const b of document.querySelectorAll("button[data-action]")) {
  b.addEventListener("click", () => run(b.dataset.path, {}));
}

for (const form of document.querySelectorAll("form[data-path]")) {
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const body = {};
    for (const el of form.querySelectorAll("input[name], select[name]")) {
      body[el.name] = el.type === "number" ? Number(el.value) : el.value;
    }
    run(form.dataset.path, body);
  });
}
