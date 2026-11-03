# Runbook — Content signals

**Milestone:** M27 ([G0 M27](../g0/M27.md) D503–D505, D507, D512, D532, D533, D552, D553; [ADR-0050](../adr/0050-content-signals-boundary-amendment.md)). **Audience:** Security Admins and gateway operators. **Edition:** turning a mode on needs Business (`ContentSignals()`).

Content signals scan tool results and outbound bodies on the gateway for listed phrases and formats. A flag can only restrict. A result with no flags reads "no known flags", never "clean" or "safe".

## What scanning misses

- The built-in classifier knows listed phrases and formats only. Re-encoded (base64 or another encoding), split (across arguments, calls or results) or paraphrased content passes.
- Hook, SDK, AuthZEN and local connections are not scanned in any mode, and delegated outcomes are not inspected. Content that reaches an agent through them carries no flag and holds nothing, and it shows as not inspected, never "no known flags". AuthZEN is not scanned because its enforcement point dispatches the call itself, so the gateway never sees the body.
- A flag is an inference. No flags means "no known flags", nothing more.

## Settings

- Service `pantherclaw.v1.ContentSignalService`:
  - `GetSettings` needs `content.read`: Org Admin, Security Admin, Auditor;
  - `SetMode` needs `content.manage`: Security Admin, and a person only. A service account is refused `CONTENT_HUMAN_ONLY`.
- Modes:
  - **OFF** is the default and scans nothing;
  - **WATCHING** records flags and raises alerts, and changes no decision;
  - **ACTIVE** acts on flags.
- OFF moves only to WATCHING. ACTIVE is reached only from WATCHING (otherwise `CONTENT_WATCH_FIRST`) and needs a fresh security-key step-up.
- Turning a mode on needs Business, otherwise `EDITION_REQUIRED`. Turning it down needs no edition.
- On a lapse the mode stays as it is, and gateways and the Authority keep honouring it until a person turns it off.
- Leaving ACTIVE (to WATCHING or OFF) files a protected change on surface `content.signals.mode`. Nothing changes until a second person confirms. With no Gate configured, the change is refused.
- Every applied change writes the audit event `content.signals.mode_changed` (old mode, new mode, reason) and bumps the gateways' configuration version, so gateways pick up the mode.
- Settings show `would_hold`, counted only in WATCHING: per reason, a count with first and last time. The reasons are each finding kind, `over_bound`, `classifier_unavailable`, `builtin_failed`, `not_scanned` and `unknown_kind`. Read them before the step-up to ACTIVE: they are what ACTIVE would have held.
- Settings list `not_inspected` (hook, sdk, authzen, local, delegated) with a note that says what passes.

## Before moving to ACTIVE

1. **Upgrade every gateway first.** In ACTIVE, a call on a gateway-carried channel without the gateway's SCANNED marker holds. A gateway from before M27, or one whose configuration fetch failed and still thinks the mode is OFF, fails closed.
2. Run WATCHING long enough to see real traffic, and read `would_hold`.
3. A result flag recorded in WATCHING stays on its run. Once the organization moves to ACTIVE, it holds later writes on that run's tree.

## What the gateway scans

- The gateway reads the mode from its configuration (`content_signal_mode`) and scans only gateway-carried calls.
- It scans outbound action arguments before the decision (location prefix `arg`) and the tool result as the agent gets it, with the credential removed (location prefix `result`).
- **The raw body is always scanned:** a JSON body string by string, with JSON escapes decoded, and anything else as text. A body that looks like server-sent events, as an MCP server may send, gets an extra pass that walks each event's data as JSON. Findings of both passes merge.
- Bound: 64 KiB per body. A larger body is `scan_incomplete` with reason `over_bound`.
- A finding is a kind and a location, at most 16 per body. No value or excerpt is stored, logged, exported or sent to the server.
- Kinds: `injection_phrase`, `secret_format`, `high_entropy`, `pii_email`, `pii_card`, `pii_national_id`, `classifier_flag` and `scan_incomplete`. A kind outside this list, or a malformed location, is stored as `scan_incomplete` with reason `unknown_kind`, never as sent.

## An out-of-process classifier (optional)

- Set it in the gateway's own configuration, section `content_signals`. The server never pushes it.
  - `classifier_url`: http or https, an IP literal on loopback or a private address, no user info;
  - `classifier_timeout`: default 250 ms, at most 5 s. The HTTP client also has its own 5 s timeout.
- The gateway posts JSON `{surface, location, content_base64}` and expects `{"flags":[{"location": "..."}]}`. Every flag is `classifier_flag`.
- **A classifier's location is kept only when it is the location the gateway asked about, or one the built-in gives for the same body** (the location of a JSON string in it). Anything else is replaced by the location asked about, so a classifier that echoes a value keeps none of it.
- If the classifier fails or times out, the built-in keeps running and the finding is `scan_incomplete` with reason `classifier_unavailable`. If the built-in fails, the reason is `builtin_failed`.
- There is no third-party API adapter and no model inside the gateway. The classifier is yours to run and to trust.

## What a flag does

- **ACTIVE:**
  - an outbound flag, `scan_incomplete` included, holds that action now: REQUIRE_APPROVAL with code `CONTENT_FLAG_HOLD` and an approver;
  - a result flag lands as the fact `pc.content.flag` on the root run of the tree. Later writes on any run of the tree hold; reads pass;
  - a tool result over 64 KiB still reaches the agent, but its `scan_incomplete` flag lands on the run and holds later writes on the run tree;
  - the policy attribute `run.content_flags` (a list of kinds) lets your own rule deny.
- **WATCHING:** no decision changes. The checklist notes `CONTENT_FLAG_WATCHING`, and `run.content_flags` is empty.
- Nothing allows or lifts on a flag, and a flag never turns a denial into a hold. Each hold is approved per action. A mode that cannot be read is CANNOT_AUTHORIZE.
- The agent sees only the code `CONTENT_FLAG_HOLD`, never a kind or location.
- Only the built-in provider writes `pc.content.flag`. No RPC or other fact provider can.

## People's side

- An alert per run and kind, basis INFERRED, titled "Content flag (inference): KIND". Automations never contain on it; a person decides.
- Owned failure `content.scan_incomplete`, one per reason, in WATCHING and ACTIVE.
- Investigations show content provenance as NOT_COLLECTED, FLAGGED, NO_KNOWN_FLAGS or NOT_INSPECTED. Never "clean" or "safe".

## Data

Migration `00302` adds `pc.content_signal_settings` and `pc.content_signal_would_holds`, with row-level security and the organization write guard.
