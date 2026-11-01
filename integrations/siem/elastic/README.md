# PantherClaw rules for Elastic Security

`rules.ndjson` is a detection rule export of KQL rules. `ingest-pipeline.json` sets `@timestamp` from the event's `time`. `index-template.json` maps the fields the rules read and sends the data stream `logs-pantherclaw.ocsf-*` through the pipeline.

## Install

1. Create the pipeline and the template:

   ```
   PUT _ingest/pipeline/pantherclaw-ocsf      (body: ingest-pipeline.json)
   PUT _index_template/pantherclaw-ocsf       (body: index-template.json)
   ```

2. Have your collector (see the [main README](../README.md)) index each OCSF event into `logs-pantherclaw.ocsf-default`.
3. In Kibana, open Security, then Rules, and import `rules.ndjson`.
4. Enable the rules you want. They ship disabled.

## What was not checked

- The import, the pipeline and the template have not been tried on an Elastic cluster.
- The KQL has not run in Kibana. A test reads the queries and evaluates them over the samples, which checks the logic and not Kibana's parsing.
- There is no Elastic integration package and no prebuilt rule listing.
