// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// Secret forms (G0 M22 D57). Loaded after integrations.js, whose post,
// stepUp, say and explain it uses. It steps up with a security key, then
// sends the form as same-origin JSON with the PC-CSRF header (HR-151). The
// path comes from the server-rendered form, never the URL, and secret fields
// are cleared whatever the answer.
"use strict";

function formBody(form) {
  const body = {};
  for (const el of form.querySelectorAll("input[name], select[name]")) {
    if (el.dataset.list) {
      body[el.name] = body[el.name] || [];
      if (el.checked) { body[el.name].push(el.value); }
    } else if (el.type === "checkbox") {
      body[el.name] = el.checked;
    } else {
      body[el.name] = el.value;
    }
  }
  return body;
}

function clearSecrets(form) {
  for (const el of form.querySelectorAll('input[type="password"]')) { el.value = ""; }
}

function samePath(p) { return typeof p === "string" && p.startsWith("/") && !p.startsWith("//"); }

const secretForm = document.getElementById("secret-form");
if (secretForm) {
  secretForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      say("Waiting for your security key…");
      await stepUp();
      const res = await post(secretForm.dataset.path, formBody(secretForm));
      if (samePath(res.change_path)) {
        // Filed as a protected change: the form has done its work.
        document.getElementById("secret-change-link").href = res.change_path;
        document.getElementById("secret-change").hidden = false;
        secretForm.hidden = true;
        say("Saved.");
        return;
      }
      say(res.state === "PENDING" ? "Saved. It stays pending until it is activated." : "Saved. The credential is replaced.");
      if (samePath(res.next)) { window.location.assign(res.next); }
    } catch (e) {
      say(e instanceof APIError ? explain(e) : "The security key did not answer (" + e.message + ").");
    } finally {
      clearSecrets(secretForm);
    }
  });
}
