# PantherClaw rules for Wazuh

`pantherclaw_rules.xml` holds three kinds of rule:

- A parent rule on Wazuh's JSON decoder.
- A child that stops simulated events.
- One child per detection rule.

It uses ids 100700 to 100799 from the custom range: change them if they clash with yours.

## Install

1. Copy `pantherclaw_rules.xml` to `/var/ossec/etc/rules/` on the manager.
2. Get events in as the next section says.
3. Restart the manager.

Unlike the other packs, these rules go live as soon as you load them, because Wazuh has no disabled state for a rule. They raise alerts and start no active response. Remove any rule you don't want.

## Ingest

PantherClaw posts each batch as one JSON body: `{"type":"pantherclaw.ocsf.batch","data":{…,"events":[…]}}`.

**Wazuh can't split it.** Wazuh has no HTTP input for logs, and a decoder reads one log line into one event, so no decoder turns a batch into its events. A whole batch written as one line decodes as one event whose fields sit under `data.events`, and none of these rules fires on it.

The rules expect one OCSF event per line, in the layout of the files in `../samples/`, with field names unchanged. Wazuh's built-in JSON decoder reads that, so no custom decoder is needed. An agent reads the file:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/pantherclaw/ocsf.json</location>
</localfile>
```

Whatever receives PantherClaw's POST must write each entry of `data.events` as one line of that file.

**The webhook signature is not verified** by Wazuh, which never sees it. A verifying forwarder that ships with PantherClaw is a later piece. Until then, whatever you run in front must check the signature itself, or Wazuh will trust whatever lands in the file.

## What was not checked

- The rules have not been loaded by `wazuh-analysisd` or run through `wazuh-logtest`.
- A test reads the XML and evaluates the fields with Go's regular expressions, not PCRE2. It assumes that the first child that matches takes the event, and that the JSON decoder joins an array with commas.
- The child that stops simulated events relies on that order. Try one in `wazuh-logtest` before you trust it.
