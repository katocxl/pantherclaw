# PantherClaw rules for Microsoft Sentinel

`analytic-rules.json` is an ARM template of scheduled analytics rules. `table.json` is the schema of the custom table they read: `PantherClawOCSF_CL`, with `TimeGenerated` and one dynamic column, `Ocsf`, holding the whole event.

## Install

1. Create the table from `table.json` in your Log Analytics workspace.
2. Create a data collection endpoint and rule for the Logs Ingestion API, with a stream for that table. Neither is included here, as both depend on your Azure setup.
3. Have your collector (see the [main README](../README.md)) send each OCSF event with `Ocsf` set to the event and `TimeGenerated` to its time.
4. Deploy the rules, giving your workspace name:

   ```
   az deployment group create --resource-group <group> --template-file analytic-rules.json --parameters workspace=<workspace>
   ```

5. Enable the rules you want. They ship disabled.

## What was not checked

- The template has not been deployed, and the `apiVersion` it names has not been tried against a live workspace.
- The KQL has not run in Log Analytics. A test reads its `where` clauses and evaluates them over the samples, which checks the logic and not KQL's parsing.
- There is no Content Hub solution.
