// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// The index is fetched on first use; all matching and display stay local.
const script = document.querySelector("script[data-index]");
const input = document.querySelector("#search");
const results = document.querySelector("#results");
const status = document.querySelector("#search-status");
let index;
let generation = 0;
document.querySelector("form[role=search]").addEventListener("submit", (event) => event.preventDefault());
input.addEventListener("input", async () => {
  const current = ++generation;
  const words = input.value.toLowerCase().trim().split(/\s+/).filter(Boolean).slice(0, 8);
  results.replaceChildren();
  results.hidden = words.length === 0;
  status.textContent = "";
  if (!words.length) return;
  try {
    index ??= fetch(script.dataset.index).then((response) => {
      if (!response.ok) throw new Error("index unavailable");
      return response.json();
    });
    const pages = await index;
    if (current !== generation) return;
    const matches = pages.filter((page) => words.every((word) => `${page.title} ${page.text}`.toLowerCase().includes(word)));
    for (const page of matches.slice(0, 30)) {
      const item = document.createElement("li");
      const link = document.createElement("a");
      link.href = script.dataset.root + page.url;
      link.textContent = page.title;
      item.append(link);
      results.append(item);
    }
    status.textContent = `${matches.length} results${matches.length > 30 ? "; showing the first 30" : ""}`;
  } catch {
    index = undefined;
    if (current === generation) status.textContent = "Search is unavailable. Use the guide links below.";
  }
});
