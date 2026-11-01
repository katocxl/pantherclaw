# PantherClaw rules for Wazuh

`pantherclaw_rules.xml` holds a parent rule on Wazuh's JSON decoder, a child that stops simulated events, and one child per rule. It uses ids 100700 to 100799 from the custom range: change them if they clash with yours.

## Install

1. Copy `pantherclaw_rules.xml` to `/var/ossec/etc/rules/` on the manager.
2. Have your collector (see the [main README](../README.md)) append each OCSF event as one JSON line to a file an agent reads:

   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>/var/log/pantherclaw/ocsf.json</location>
   </localfile>
   ```

3. Restart the manager.

Unlike the other packs these rules are live as soon as you load them, as Wazuh has no disabled state for a rule. They raise alerts and start no active response. Remove any rule you don't want.

## What was not checked

- The rules have not been loaded by `wazuh-analysisd` or run through `wazuh-logtest`.
- A test reads the XML and evaluates the fields with Go's regular expressions, not PCRE2. It assumes that the first child that matches takes the event, and that the JSON decoder joins an array with commas.
- The child that stops simulated events relies on that order. Try one in `wazuh-logtest` before you trust it.
