// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// Approval page actions (G0 M5 part 2, HR-033, HR-151, HR-172). Approving
// is a WebAuthn assertion whose challenge is the request's binding (the
// server stores the ceremony; the page only relays it). Declining, asking
// for evidence and proposing a narrower action are same-origin JSON
// requests with the PC-CSRF header. The page runs under Trusted Types:
// text is written with textContent only, and nothing is read from the URL.
"use strict";

class APIError extends Error {
  constructor(code, reason) {
    super(code);
    this.code = code;
    this.reason = reason || "";
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
  if (!res.ok) { throw new APIError(data.error || ("http_" + res.status), data.reason); }
  return data;
}

function say(text) {
  const el = document.getElementById("status");
  if (el) { el.textContent = text; }
}

const messages = {
  not_found: "This request does not exist, or you cannot see it.",
  not_eligible: "You cannot decide this request (you may have responded already, or a cooldown applies).",
  not_waiting: "The request is no longer waiting. Reload the page.",
  human_session: "Sign in again in this browser.",
  invalid: "Choose a reason and keep the note under 500 characters.",
  evidence_deadline: "The evidence must be due before the request's deadline. Choose a shorter time.",
  evidence_limit: "The request has its maximum of evidence notes.",
  proposal_unavailable: "This request cannot take a narrower proposal.",
  not_narrower: "The proposal must keep every parameter and only lower amounts, integers or lists.",
  no_keys: "You need a security key on your account first (add one on your account page).",
  ceremony_invalid: "The security key request expired or was already used. Try again.",
  verification_failed: "The security key's answer could not be verified.",
  key_suspended: "That security key is suspended. Use another key or ask an administrator.",
  bad_request: "The request was not understood.",
  edition_required: "Batch approval needs the Team edition or above.",
  batch_invalid: "Select 1 to 25 requests for one operation.",
};

function explain(e) {
  if (e.code === "not_batchable") {
    return "One of the selected requests must be reviewed on its own page (" + e.reason + ").";
  }
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

function value(id) {
  const el = document.getElementById(id);
  return el ? el.value.trim() : "";
}

function on(id, f) {
  const el = document.getElementById(id);
  if (el) { el.addEventListener("click", () => f(el.dataset.id)); }
}

function base(id) { return "/approvals/" + encodeURIComponent(id); }

// approve signs the request's binding with a security key.
async function approve(id) {
  try {
    say("Waiting for your security key…");
    const c = await post(base(id) + "/approve-options");
    const cred = await navigator.credentials.get({ publicKey: requestOptions(c.options.publicKey) });
    const out = await post(base(id) + "/approve", { ceremony: c.ceremony, response: credentialJSON(cred) });
    say(out.state === "APPROVED" ? "Approved." : "Your approval is recorded. More approvals are needed.");
    window.location.reload();
  } catch (e) {
    say(e instanceof APIError ? explain(e) : "The security key did not answer (" + e.message + ").");
  }
}

async function act(path, body, done) {
  try {
    await post(path, body);
    say(done);
    window.location.reload();
  } catch (e) {
    say(explain(e));
  }
}

// narrower checks a proposal (or proposes it) and shows the decision the
// agent would get, as text.
async function narrower(id, validateOnly) {
  const out = document.getElementById("narrower-result");
  let params;
  try { params = JSON.parse(value("narrower-params")); } catch (e) { say("The parameters are not valid JSON."); return; }
  try {
    const r = await post(base(id) + "/narrower", { params: params, note: value("narrower-note"), validate_only: validateOnly });
    if (out) {
      out.textContent = "Decision for the agent: " + r.decision + (r.reasons.length ? " (" + r.reasons.join(", ") + ")" : "") +
        "\nParameters: " + JSON.stringify(r.params, null, 2);
    }
    say(validateOnly ? "Checked. Nothing was recorded." : "Proposed. The request has ended.");
    if (!validateOnly) { window.location.reload(); }
  } catch (e) {
    say(explain(e));
  }
}

on("approve", approve);
on("decline", (id) => act(base(id) + "/decline", {
  reason: value("decline-reason"), alternative: value("decline-alternative"), note: value("decline-note"),
}, "Declined."));
on("request-evidence", (id) => act(base(id) + "/evidence-request", {
  question: value("evidence-question"), note: value("evidence-note"), minutes: parseInt(value("evidence-minutes"), 10),
}, "Evidence requested."));
on("narrower-check", (id) => narrower(id, true));
on("narrower-propose", (id) => narrower(id, false));

// approveBatch signs the hash of the selected requests' bindings with one
// security-key assertion (HR-175, Team edition).
async function approveBatch() {
  const list = Array.from(document.querySelectorAll("input.batch:checked")).map((el) => el.value);
  if (list.length === 0) {
    say("Select the requests to approve.");
    return;
  }
  try {
    say("Waiting for your security key…");
    const c = await post("/approvals/batch-options", { ids: list });
    const cred = await navigator.credentials.get({ publicKey: requestOptions(c.options.publicKey) });
    const out = await post("/approvals/batch", { batch: c.batch, ceremony: c.ceremony, response: credentialJSON(cred) });
    say(out.approved + " requests approved.");
    window.location.reload();
  } catch (e) {
    say(e instanceof APIError ? explain(e) : "The security key did not answer (" + e.message + ").");
  }
}

const batchButton = document.getElementById("approve-batch");
if (batchButton) { batchButton.addEventListener("click", approveBatch); }
