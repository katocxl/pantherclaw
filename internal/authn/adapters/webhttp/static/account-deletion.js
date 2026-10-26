// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
"use strict";
for (const [id,path] of [["reauth-account","/account/delete/reauth"],["delete-account","/account/delete"]]) {
  const button=document.getElementById(id);
  if (!button) continue;
  button.addEventListener("click", async () => {
    button.disabled=true;
    try {
      const response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","PC-CSRF":"1"},body:"{}"});
      const result=await response.json();
      if (!response.ok) {
        document.getElementById("status").textContent=result.error==="last_org_admin" ? "Assign another organization administrator, then sign in again to retry." : "Unable to complete deletion. Sign in again to retry.";
        button.disabled=false;
        return;
      }
      window.location.assign(result.next);
    } catch (_) {
      document.getElementById("status").textContent="Unable to reach the server. Try again.";
      button.disabled=false;
    }
  });
}
