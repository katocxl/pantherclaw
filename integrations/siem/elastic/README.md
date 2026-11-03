# PantherClaw rules for Elastic Security

`rules.ndjson` is a detection rule export of KQL rules. `ingest-pipeline.json` sets `@timestamp` from the event's `time`. `index-template.json` maps the fields the rules read and sends the data stream `logs-pantherclaw.ocsf-*` through the pipeline. `logstash/pantherclaw-batch.conf` splits an export batch into one document per event.

## Install

1. Create the pipeline and the template:

   ```
   PUT _ingest/pipeline/pantherclaw-ocsf      (body: ingest-pipeline.json)
   PUT _index_template/pantherclaw-ocsf       (body: index-template.json)
   ```

2. Get batches in as the next section says.
3. In Kibana, open Security, then Rules, and import `rules.ndjson`.
4. Enable the rules you want. They ship disabled.

## Ingest

PantherClaw posts each batch as one JSON body: `{"type":"pantherclaw.ocsf.batch","data":{…,"events":[…]}}`. An Elasticsearch ingest pipeline can't turn one document into several, so the split happens in Logstash.

`logstash/pantherclaw-batch.conf` does the following:

- It listens for HTTPS. Set your port, certificate and key.
- It drops any body that isn't a batch, and splits `data.events` into one event each.
- It moves every top-level OCSF field to the root and removes the envelope and Logstash's own request fields.
- It indexes each event into `logs-pantherclaw.ocsf-default`, where the template's pipeline sets `@timestamp`. Set your `hosts` and credentials in the output.

**The webhook signature is not verified.** Logstash doesn't read the Standard Webhooks headers, so anyone who can reach the input can write events that the rules will trust. `pclaw siem forward` verifies it, but it writes the events to a file ([runbook](../../../docs/runbooks/siem-forwarder.md)), which this pack's Logstash pipeline doesn't read. Without it, keep the input reachable only from PantherClaw, for example behind a proxy you run that checks the source.

## What was not checked

- The import, the pipeline, the template and the Logstash pipeline have not been tried on an Elastic cluster or a Logstash instance.
- The KQL has not run in Kibana. A test reads the queries and evaluates them over the samples, which checks the logic and not Kibana's parsing.
- A test reads the Logstash split, renames and removals and applies them to `../samples/batch/batch.json`: each document comes out as a sample. That assumes `split` and `mutate` behave as Logstash documents them. Which request fields the `http` input adds depends on your Logstash version and ECS mode.
- There is no Elastic integration package and no prebuilt rule listing.
