# PantherClaw rules for Microsoft Sentinel

`analytic-rules.json` is an ARM template of scheduled analytics rules. `table.json` is the schema of the custom table they read: `PantherClawOCSF_CL`, with `TimeGenerated` and one dynamic column, `Ocsf`, holding the whole event. `dcr.json` is a data collection rule that fills that table from OCSF events sent to the Logs Ingestion API.

## Install

1. Create the table from `table.json` in your Log Analytics workspace.
2. Get events in as the next section says.
3. Deploy the rules, giving your workspace name:

   ```
   az deployment group create --resource-group <group> --template-file analytic-rules.json --parameters workspace=<workspace>
   ```

4. Enable the rules you want. They ship disabled.

## Ingest

PantherClaw posts each batch as one JSON body: `{"type":"pantherclaw.ocsf.batch","data":{…,"events":[…]}}`.

**Sentinel can't split it.** A data collection rule's transformation runs on one record at a time and returns at most one row, so no rule turns a batch into its events. The Logs Ingestion API also requires a Microsoft Entra bearer token, which the export doesn't send. PantherClaw therefore cannot post to Sentinel directly.

### Through `pclaw siem forward` and the Azure Monitor Agent

`pclaw siem forward` receives the export, verifies each batch and appends each of its OCSF events as one line to a file ([runbook](../../../docs/runbooks/siem-forwarder.md)). The Azure Monitor Agent reads that file as a custom text log, one record per line.

1. On a machine with the Azure Monitor Agent, run the forwarder with the destination's signing secret, writing to a file the agent can read:

   ```
   pclaw siem forward --listen 10.0.0.5:8471 --tls-cert forwarder.crt --tls-key forwarder.key \
     --secret-file /etc/pantherclaw/siem.secret --out /var/log/pantherclaw/ocsf.json
   ```

2. Point the SIEM destination at `https://10.0.0.5:8471/`. A private address makes it an internal destination, confirmed with a security key ([SIEM export runbook](../../../docs/runbooks/siem-export.md)).
3. Create a data collection rule with a custom text log data source for `/var/log/pantherclaw/ocsf.json`, sending to `PantherClawOCSF_CL`. Each line arrives as `RawData`; this transformation turns it into the table's two columns:

   ```
   source
   | extend Ocsf = parse_json(RawData)
   | extend TimeGenerated = datetime(1970-01-01) + tolong(Ocsf.time) * 1ms
   | project TimeGenerated, Ocsf
   ```

4. Associate the rule with the machine.

### Through the Logs Ingestion API

`dcr.json` takes the step after the split: one OCSF event per record. Its stream declares every top-level OCSF field, and its transformation packs them back into `Ocsf` and sets `TimeGenerated` from `time`. `data.events` is already the JSON array the Logs Ingestion API accepts. So whatever sits in between posts that array, as it stands, to the rule's endpoint for the stream `Custom-PantherClawOCSF`, with a token. Set your region and workspace resource id in `dcr.json`, then create the rule:

```
az monitor data-collection rule create --resource-group <group> --name pantherclaw-ocsf --rule-file dcr.json
```

**The webhook signature is not verified** by Sentinel, which never sees it. `pclaw siem forward` verifies it before it writes a line: the HMAC signature, and the Ed25519 one as well when it is given the org's JWKS, within a timestamp window, answering a re-sent batch without writing it again. Whatever else writes to the file or posts to the Logs Ingestion API is trusted as it is: keep the file writable only by the forwarder, and anything you run in front of the API must check the signature itself.

## What was not checked

- The template and the data collection rule have not been deployed, and the `apiVersion` the template names has not been tried against a live workspace.
- The KQL has not run in Log Analytics. A test reads the rules' `where` clauses and evaluates them over the samples, which checks the logic and not KQL's parsing.
- A test checks that the data collection rule declares and packs every top-level OCSF field with a type that fits each sample. The transformation itself has not run.
- The Azure Monitor Agent route has not run: no agent has read the forwarder's file, and the transformation above has not run. A test checks only that the forwarder writes each event of the exporter's batch as one line.
- There is no Content Hub solution.
