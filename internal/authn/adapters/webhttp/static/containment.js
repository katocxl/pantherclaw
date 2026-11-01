// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// Emergency-stop page actions (G0 M6, HR-113). Each action first steps up
// with a security key (WebAuthn, user verification), then sends a
// same-origin JSON request with the PC-CSRF header (HR-151). The page runs
// under Trusted Types: text is written with textContent only.
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
  forbidden: "You do not hold the Emergency Responder role.",
  already_engaged: "The kill switch is already engaged.",
  not_engaged: "The kill switch is not engaged.",
  restore_pending: "A restore is already waiting for confirmation.",
  restore_gone: "That proposal was decided, canceled or expired. Reload the page.",
  same_person: "A different person must confirm the restore.",
  same_key: "The confirmation needs a different security key from the proposal's.",
  reason_required: "Give a reason of 1 to 500 characters.",
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

function value(id) {
  const el = document.getElementById(id);
  return el ? el.value.trim() : "";
}

function on(id, f) {
  const el = document.getElementById(id);
  if (el) { el.addEventListener("click", () => f(el)); }
}

on("engage", () => act("/containment/kill-switch/engage", { reason: value("engage-reason") }, "The kill switch is engaged."));
on("propose-restore", () => act("/containment/kill-switch/restore", { reason: value("restore-reason") }, "Restore proposed."));
on("confirm-restore", (el) => act("/containment/kill-switch/restore/" + el.dataset.id + "/confirm", {}, "The kill switch is lifted."));
on("cancel-restore", async (el) => {
  try {
    await post("/containment/kill-switch/restore/" + el.dataset.id + "/cancel", {});
    window.location.reload();
  } catch (e) {
    say(explain(e));
  }
});
