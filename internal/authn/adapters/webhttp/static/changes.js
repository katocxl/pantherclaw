// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// Change request page actions (G0 M11 part 2 D6, HR-272, HR-151).
// Confirming a change is a WebAuthn assertion whose challenge is the change
// request's binding (the server computes it and stores the ceremony; the
// page only relays it). Requests are same-origin JSON with the PC-CSRF
// header. The page runs under Trusted Types: text is written with
// textContent only, and nothing is read from the URL.
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
  not_found: "This change request does not exist, or you cannot see it.",
  not_permitted: "You cannot confirm or decline it: that needs every permission the change uses where it acts.",
  not_eligible: "You cannot confirm it: it needs permissions you do not hold where it acts.",
  compromised: "You are marked as a compromised publisher and cannot confirm changes.",
  human_session: "Sign in again in this browser.",
  same_person: "You already confirmed this change; another person must confirm it.",
  same_key: "That security key already confirmed this change; another person's key is needed.",
  expired: "This change request has expired. Ask for it again.",
  not_pending: "This change request has ended. Reload the page.",
  voided: "The change request was voided: what it would change is no longer what was confirmed. Ask for it again.",
  not_applied: "The change could not be applied. Reload the page.",
  invalid_reason: "Write a reason of 1 to 500 characters.",
  unavailable: "This kind of change is not available on this server.",
  no_keys: "You need a security key on your account first (add one on your account page).",
  ceremony_invalid: "The security key request expired or was already used. Try again.",
  verification_failed: "The security key's answer could not be verified.",
  key_suspended: "That security key is suspended. Use another key or ask an administrator.",
  bad_request: "The request was not understood.",
};

function explain(e) {
  return messages[e.code] || ("Something went wrong (" + e.message + ").");
}

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

function base(id) { return "/changes/" + encodeURIComponent(id); }

// confirm signs the change request's binding with a security key.
async function confirm(id) {
  try {
    say("Waiting for your security key…");
    const c = await post(base(id) + "/confirm-options", {});
    const cred = await navigator.credentials.get({ publicKey: requestOptions(c.options.publicKey) });
    const out = await post(base(id) + "/confirm", { ceremony: c.ceremony, response: credentialJSON(cred) });
    say(out.state === "APPROVED" ? "Confirmed: the change is now in effect." :
      "Confirmed (" + out.confirmations + " of " + out.required + "): another person must confirm it.");
    window.location.reload();
  } catch (e) {
    say(e instanceof APIError ? explain(e) : "The security key did not answer (" + e.message + ").");
  }
}

// decline ends the change request with a reason.
async function decline(id) {
  const el = document.getElementById("decline-reason");
  const reason = el ? el.value.trim() : "";
  if (reason === "") {
    say(messages.invalid_reason);
    return;
  }
  try {
    await post(base(id) + "/decline", { reason: reason });
    say("Declined.");
    window.location.reload();
  } catch (e) {
    say(e instanceof APIError ? explain(e) : "Something went wrong (" + e.message + ").");
  }
}

const confirmButton = document.getElementById("confirm");
if (confirmButton) { confirmButton.addEventListener("click", () => confirm(confirmButton.dataset.id)); }
const declineButton = document.getElementById("decline");
if (declineButton) { declineButton.addEventListener("click", () => decline(declineButton.dataset.id)); }
