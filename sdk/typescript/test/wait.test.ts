// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

import assert from "node:assert/strict";
import { test } from "node:test";
import { next, parseWaitResponse, readStream, retry } from "../src/client.ts";
import { load } from "./vectors.ts";

test("conformance exchanges: token issuance, long-polls and the SSE stream", async () => {
  const f = await load("sdk_face.json");
  for (const e of f.exchanges) {
    let got: string = retry(e.status, new Headers(e.headers ?? {}));
    let states: string[] = [];
    if (got) {
      // the one retry a 401 allows
    } else if (e.outcome === "token") {
      const t = JSON.parse(e.body) as { workloadToken: string; expireTime: string };
      assert.equal(t.workloadToken, e.token, e.name);
      assert.equal(Date.parse(t.expireTime) / 1000, e.expires_at, e.name);
      got = "token";
    } else if (e.path.startsWith("/v1/wait/")) {
      const stream = new Blob([e.body]).stream();
      await readStream(stream, (w) => {
        states.push(w.state ?? "");
        got = next(w);
        return true;
      });
    } else {
      const { state } = parseWaitResponse(e.body);
      states = [state.state ?? ""];
      got = next(state);
    }
    assert.equal(got, e.outcome, e.name);
    assert.deepEqual(states, e.states ?? [], e.name);
  }
});
