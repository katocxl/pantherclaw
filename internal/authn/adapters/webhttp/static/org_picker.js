// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// Org picker actions (G0 UI D8). Every state-changing request is a
// same-origin fetch with the PC-CSRF header and a JSON body (HR-151). The
// page runs under Trusted Types: text is written with textContent only.
"use strict";

// sameOrigin is the client side of the server's return-path rule: a path
// on this origin, never "//" (another host), never a backslash, which
// browsers may read as a slash, and never a control character (C0 or DEL;
// browsers drop tab, CR and LF from URLs, which can join "/" and "/").
function sameOrigin(p, prefix) {
  return typeof p === "string" && p.startsWith(prefix) && !p.startsWith("//") && !p.includes("\\") &&
    !/[\u0000-\u001f\u007f]/.test(p);
}

async function post(path) {
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "PC-CSRF": "1" },
    body: "{}",
  });
  let data = {};
  try { data = await res.json(); } catch (e) { data = {}; }
  if (!res.ok) {
    // HR-353: a sign-in too old to pick an org starts a fresh sign-in to
    // the same org; only a same-origin sign-in path is followed.
    if (data.error === "sign_in_again" && sameOrigin(data.sign_in, "/login?")) {
      window.location.assign(data.sign_in);
      return new Promise(() => {});
    }
    throw new Error(data.error || ("http_" + res.status));
  }
  return data;
}

function say(text) {
  const el = document.getElementById("status");
  if (el) { el.textContent = text; }
}

const messages = {
  not_pickable: "This organization cannot be opened from this sign-in.",
  unauthenticated: "Your sign-in ended. Sign in again.",
};

// The page the sign-in asked to return to; the server validates it again.
const list = document.querySelector("ul.orgs");
const next = list && list.dataset.next ? list.dataset.next : "";

for (const b of document.querySelectorAll("button.pick-org")) {
  b.addEventListener("click", async () => {
    try {
      const q = next ? "?next=" + encodeURIComponent(next) : "";
      const out = await post("/login/orgs/" + encodeURIComponent(b.dataset.org) + q);
      window.location.assign(sameOrigin(out.next, "/") ? out.next : "/account");
    } catch (e) {
      say(messages[e.message] || ("Something went wrong (" + e.message + ")."));
    }
  });
}

const signOut = document.getElementById("account-sign-out");
if (signOut) {
  signOut.addEventListener("click", async () => {
    try {
      await post("/login/orgs/sign-out");
    } catch (e) {
      // Signed out either way.
    }
    window.location.assign("/signed-out");
  });
}
