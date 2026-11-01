# ADR-0044 — Graph evidence

**Status:** Accepted (2026-10-31; G0 M22 design decisions D11–D14, founder default H5; the [G0 M22 brief](../g0/M22.md) records them).

**Context.** M10 delivered graph data in five modes through `GetGraph`, and the console draws almost none of it. A reading of the code on `main` showed that the data is not ready to draw: nodes have no labels, CAUSAL has no authority, approval, custody or effect edges, CHANGE has no before and after, and the modes other than ACTIVITY lack gaps and some provenance. A picture carries more weight than a table. A reader takes a drawn line as a fact, so a graph can mislead where a list would not, and a name on a node can disclose what a count would not. F797 bars decorative graphs and F801 bars invented assurance.

**Decision.**
1. **Labels** (HR-550). `GraphNode.label` is plain text of at most 200 characters, taken only from names the viewer may read, and empty otherwise. Hidden records stay excluded. A label is never markup, because agents can write names (HR-340).
2. **No evidence, no link** (HR-551). CAUSAL gains the edge kinds `authorized`, `approved`, `custody`, `effect` and `triggered`. A new `evidence_ref` on GraphEdge names the receipt behind each. Where the evidence is missing the graph emits a `gap` edge rather than a link. `triggered` keeps predicted, authorized and confirmed apart, and observed never reads as possible.
3. **Gaps are data** (HR-552). Every mode returns its gaps, and every edge carries its source, observed time and freshness. Collapsing merges repeated activity, never gaps. The explicit edge states of the catalog are added.
4. **Change is shown as change.** `GraphEdge.change` (ADDED, REMOVED, KEPT, CHANGED) gives before and after for a restriction or incident scope, and compares every authority field.
5. **Additive only.** Proto changes are additive, and `buf breaking` stays clean.

**Consequences.**
- No per-dispatch credential lease record exists, so a `custody` edge is permit to transaction and does not name the credential version.
- A view can draw only what has a source, so some real events show as gaps until their evidence exists; that is the intent.
- Queries that build CAUSAL read receipts, so a graph costs more to build. D21's limit of 300 drawn nodes, with the table holding all rows, bounds the drawing, not the query.
- Clients that ignore the new fields keep working, but must not treat a missing `label` as a missing node.
- The drawing rules (D22) live in the private console stream; this ADR binds the data they draw from.

**Alternatives.** Inferring causal links from timing (invents assurance, F801); hiding gaps on collapse to keep pictures tidy (F293, F294); labels from any stored name with the viewer's filter applied later in the client (leaks through the wire); a graph library first (H5: hand-drawn SVG, since a library that injects styles can break under the console's content security policy).
