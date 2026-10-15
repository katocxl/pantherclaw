// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// Protected-change pages (G0 M11 part 2 D42, D43, D53; HR-292, HR-293).
// Applying a protected change in an emergency, or marking a publisher
// compromised, first steps up with a security key (WebAuthn, user
// verification), then sends a same-origin JSON request with the PC-CSRF
// header (HR-151). The page runs under Trusted Types: text is written with
// textContent only, and the action's path comes from the server-rendered
// page, never the URL.
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
  compromised: "You are marked compromised and cannot do this.",
  not_found: "It does not exist, or you cannot see it.",
  not_pending: "The change is no longer pending. Reload the page.",
  unavailable: "Protected changes are not available on this server.",
  edition: "Marking a compromised publisher needs the Business edition.",
  already_marked: "This person is already marked compromised.",
  invalid: "Check the person, the time (not in the future) and the reason.",
  refused: "The change was refused. Reload the page.",
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

async function act(path, body, done) {
  try {
    say("Waiting for your security key…");
    await stepUp();
    await post(path, body);
    say(done);
    window.location.reload();
  } catch (e) {
    say(e instanceof APIError ? explain(e) : "The security key did not answer (" + e.message + ").");
  }
}

const applyButton = document.getElementById("activate");
if (applyButton) { applyButton.addEventListener("click", () => act(applyButton.dataset.path, {}, "Applied.")); }

const form = document.getElementById("compromise");
if (form) {
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const since = new Date(form.elements.since.value + "Z");
    if (isNaN(since.getTime())) { say(messages.invalid); return; }
    act("/publishers/compromise", {
      user_id: form.elements.user_id.value.trim(),
      since: since.toISOString().replace(/\.\d{3}Z$/, "Z"),
      reason: form.elements.reason.value.trim(),
    }, "Marked compromised.");
  });
}
