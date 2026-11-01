# PantherClaw rules for Google Security Operations (Chronicle)

Three parts: `rules/` holds single-event YARA-L 2.0 rules over UDM, `parser/pantherclaw_ocsf.conf` is a custom parser that turns one OCSF event per log line into UDM, and `udm-map.json` says which OCSF field each UDM field the rules read comes from.

## Install

1. Create a custom log type and add `parser/pantherclaw_ocsf.conf` as its parser.
2. Have your collector (see the [main README](../README.md)) send each OCSF event as one raw log line.
3. Upload the rules in `rules/`. A rule does nothing until you enable it.

## What was not checked

This is the least proven pack. Read this before you rely on it.

- **The parser has never run.** It was written offline and no parser validator has seen it. Expect to fix it in the parser editor with a sample from `../samples/`. A test checks only that it mentions every field `udm-map.json` names.
- **The rules have not been compiled.** A test reads them and evaluates them over the samples through `udm-map.json`. That assumes the parser does what the map says.
- UDM's required fields for `GENERIC_EVENT` have not been checked against a live tenant.
- Whether Chronicle offers a built-in OCSF parser that would replace this one has not been checked.
