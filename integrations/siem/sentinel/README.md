# PantherClaw rules for Microsoft Sentinel

`analytic-rules.json` is an ARM template of scheduled analytics rules. `table.json` is the schema of the custom table they read: `PantherClawOCSF_CL`, with `TimeGenerated` and one dynamic column, `Ocsf`, holding the whole event. `dcr.json` is a data collection rule that fills that table from OCSF events sent to the Logs Ingestion API.

## Install

1. Create the table from `table.json` in your Log Analytics workspace.
2. In `dcr.json`, set your region and workspace resource id, then create the rule:

   ```
   az monitor data-collection rule create --resource-group <group> --name pantherclaw-ocsf --rule-file dcr.json
   ```

3. Get events in as the next section says.
4. Deploy the rules, giving your workspace name:

   ```
   az deployment group create --resource-group <group> --template-file analytic-rules.json --parameters workspace=<workspace>
   ```

5. Enable the rules you want. They ship disabled.

## Ingest

PantherClaw posts each batch as one JSON body: `{"type":"pantherclaw.ocsf.batch","data":{…,"events":[…]}}`.

**Sentinel can't split it.** A data collection rule's transformation runs on one record at a time and returns at most one row, so no rule turns a batch into its events. The Logs Ingestion API also requires a Microsoft Entra bearer token, which the export doesn't send. PantherClaw therefore cannot post to Sentinel directly.

`dcr.json` takes the step after the split: one OCSF event per record. Its stream declares every top-level OCSF field, and its transformation packs them back into `Ocsf` and sets `TimeGenerated` from `time`. `data.events` is already the JSON array the Logs Ingestion API accepts. So whatever sits in between posts that array, as it stands, to the rule's endpoint for the stream `Custom-PantherClawOCSF`, with a token.

**The webhook signature is not verified** by Sentinel, which never sees it. A verifying forwarder that ships with PantherClaw is a later piece. Until then, whatever you run in between must check the signature itself, or Sentinel will trust whatever it is sent.

## What was not checked

- The template and the data collection rule have not been deployed, and the `apiVersion` the template names has not been tried against a live workspace.
- The KQL has not run in Log Analytics. A test reads the rules' `where` clauses and evaluates them over the samples, which checks the logic and not KQL's parsing.
- A test checks that the data collection rule declares and packs every top-level OCSF field with a type that fits each sample. The transformation itself has not run.
- There is no Content Hub solution.
