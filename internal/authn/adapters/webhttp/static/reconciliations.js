// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// Reconciliation page action (G0 M7 design decision 3, HR-192, HR-151).
// Releasing an unknown outcome is a WebAuthn assertion whose challenge is
// the release binding: this reconciliation, "did not occur", the basis the
// person wrote and the evidence the page shows (the server computes it and
// stores the ceremony; the page only relays it). Requests are same-origin
// JSON with the PC-CSRF header. The page runs under Trusted Types: text is
// written with textContent only, and nothing is read from the URL.
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
  not_found: "This reconciliation does not exist, or you cannot see it.",
  not_permitted: "You cannot release it: that needs transaction.reconcile where the agent lives.",
  not_independent: "You cannot release it: the run's launcher, the person it acted for and the agent's owners never release their own run's outcome.",
  human_session: "Sign in again in this browser.",
  not_open: "This reconciliation is already resolved. Reload the page.",
  not_releasable: "Only an unknown outcome is released.",
  invalid_basis: "Write a basis of 1 to 2000 characters.",
  evidence_changed: "The evidence changed. Reload the page and look at it again.",
  expired: "The release expired. Try again.",
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

// shown lists the observations the page shows: the evidence the release
// names.
function shown() {
  return Array.from(document.querySelectorAll("[data-evidence]")).map((el) => el.dataset.evidence);
}

function base(id) { return "/reconciliations/" + encodeURIComponent(id); }

// release signs the release binding with a security key.
async function release(id) {
  const el = document.getElementById("release-basis");
  const basis = el ? el.value.trim() : "";
  if (basis === "") {
    say(messages.invalid_basis);
    return;
  }
  try {
    say("Waiting for your security key…");
    const c = await post(base(id) + "/release-options", { basis: basis, evidence: shown() });
    const cred = await navigator.credentials.get({ publicKey: requestOptions(c.options.publicKey) });
    const out = await post(base(id) + "/release", {
      ceremony: c.ceremony, response: credentialJSON(cred), basis: basis, evidence: c.evidence, expires_at: c.expires_at,
    });
    say(out.state === "NOT_OCCURRED" ? "Released: the budget is free and an identical action will be decided again." : "Recorded.");
    window.location.reload();
  } catch (e) {
    say(e instanceof APIError ? explain(e) : "The security key did not answer (" + e.message + ").");
  }
}

const button = document.getElementById("release");
if (button) { button.addEventListener("click", () => release(button.dataset.id)); }
