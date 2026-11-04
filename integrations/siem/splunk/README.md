# PantherClaw rules for Splunk

`pantherclaw_ocsf/` is a Splunk app directory. It holds saved searches, the macro they start from, the `pantherclaw:ocsf` sourcetype they read, and a `pantherclaw:ocsf:batch` sourcetype that splits an export batch into those events.

## Install

1. Copy `pantherclaw_ocsf/` to `$SPLUNK_HOME/etc/apps/` and restart Splunk.
2. Create an index, and get batches in as the next section says.
3. If your index isn't `pantherclaw`, edit `default/macros.conf`, or better, override it in `local/macros.conf`.
4. Enable the searches you want. They ship disabled, with no alert action: add yours.

## Ingest

PantherClaw posts each batch as one JSON body: `{"type":"pantherclaw.ocsf.batch","data":{…,"events":[…]}}`. The `pantherclaw:ocsf:batch` sourcetype in `default/props.conf` and `default/transforms.conf` splits it:

- `LINE_BREAKER` starts a new event before each entry of `data.events`.
- `SEDCMD` strips the batch's closing `]}}` from the last entry.
- One transform drops the envelope to the null queue. The other files each event as `pantherclaw:ocsf`.
- `TIME_PREFIX` and `TIME_FORMAT` take the event's time from `time`, in milliseconds.

Send batches to HEC's raw endpoint, `/services/collector/raw`, with a token whose sourcetype is `pantherclaw:ocsf:batch`. Both sourcetypes must be on the instance that parses the data, which is the indexer or a heavy forwarder.

**The webhook signature is not verified.** Splunk doesn't read the Standard Webhooks headers, so anyone who can post to that endpoint with the token can write events that the searches will trust. HEC also wants its token in an `Authorization` header, which the export doesn't send. `pclaw siem forward` verifies the signature, but it writes the events to a file and adds no token ([runbook](../../../docs/runbooks/siem-forwarder.md)), so something you run must add the token. Keep the endpoint reachable only from it.

## What was not checked

- The searches have not run on a Splunk instance. A test reads the search terms and evaluates them over the samples, which checks the logic and not Splunk's parsing.
- The batch split has not run in Splunk. A test applies `LINE_BREAKER`, `SEDCMD` and the transform regexes to `../samples/batch/batch.json` with Go's regular expressions and gets the samples back byte for byte. That assumes Splunk applies them as its documentation says, and in that order.
- The `SEDCMD` assumes no event ends in `]}}`, which holds for the OCSF events PantherClaw writes today.
- `appinspect` has not run on the app, and it has no Splunkbase listing.
- The app has no `metadata/` directory, so the searches stay private to the app until you share them.
