# PantherClaw rules for Splunk

`pantherclaw_ocsf/` is a Splunk app directory: saved searches, the macro they start from, and the `pantherclaw:ocsf` sourcetype.

## Install

1. Copy `pantherclaw_ocsf/` to `$SPLUNK_HOME/etc/apps/` and restart Splunk.
2. Create an index, and an HTTP Event Collector token with sourcetype `pantherclaw:ocsf`.
3. Have your collector (see the [main README](../README.md)) send each OCSF event as the `event` of an HEC request.
4. If your index isn't `pantherclaw`, edit `default/macros.conf`, or better, override it in `local/macros.conf`.
5. Enable the searches you want. They ship disabled, with no alert action: add yours.

## What was not checked

- The searches have not run on a Splunk instance. A test reads the search terms and evaluates them over the samples, which checks the logic and not Splunk's parsing.
- `appinspect` has not run on the app, and it has no Splunkbase listing.
- The app has no `metadata/` directory, so the searches stay private to the app until you share them.
