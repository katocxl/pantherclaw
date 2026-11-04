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

`pclaw siem forward` writes that file ([runbook](../../../docs/runbooks/siem-forwarder.md)). Run it on the agent's host, with the destination's signing secret, and point the SIEM destination at it (a private address makes it an internal destination, confirmed with a security key):

```
pclaw siem forward --listen 10.0.0.5:8471 --tls-cert forwarder.crt --tls-key forwarder.key \
  --secret-file /etc/pantherclaw/siem.secret --out /var/log/pantherclaw/ocsf.json
```

It appends each event of a verified batch as one compact line, in the layout of `../samples/`, and syncs the file before it answers.

**The webhook signature is not verified** by Wazuh, which never sees it. The forwarder verifies it before it writes a line. It checks every signature it is configured with: the HMAC `v1,` signature when it is given the destination's secret, the Ed25519 `v1a,` one when it is given the org's JWKS, and both when it is given both. Given only a JWKS, it checks no HMAC. It also checks a timestamp window, and answers a re-sent batch without writing it again. Wazuh trusts whatever else lands in the file, so keep it writable only by the forwarder.

## ATT&CK and ATLAS techniques

- Per rule: a rule that names ATT&CK Enterprise techniques in `rules.yaml` has a `<mitre><id>T####</id></mitre>` block with them. A rule that names none has no block.
- Per event, both frameworks: the decoded JSON keeps `finding_info.attacks` (an alert) and `finding_info_list` (an incident) as they are; each entry has `technique.uid`, `sub_technique.uid` (when the id is a sub-technique), `tactic.uid` and `version` ("20.0" for ATT&CK, "ATLAS 2026.10" for ATLAS).

## What was not checked

- Whether this Wazuh version's MITRE database knows ATT&CK 20.0's ids (`T1685`, `T1685.002`) has not been tried; a test checks the ids equal `rules.yaml`.

- The rules have not been loaded by `wazuh-analysisd` or run through `wazuh-logtest`.
- A test reads the XML and evaluates the fields with Go's regular expressions, not PCRE2. It assumes that the first child that matches takes the event, and that the JSON decoder joins an array with commas.
- The child that stops simulated events relies on that order. Try one in `wazuh-logtest` before you trust it.
- No Wazuh agent has read a file the forwarder wrote. A test checks that the forwarder writes the packs' golden batch as exactly the files in `../samples/`, one per line.
