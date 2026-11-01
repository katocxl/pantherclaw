# PantherClaw rules for Sigma

`rules/` holds one Sigma rule per detection, with log source `product: pantherclaw`, `service: ocsf`. Field names are the OCSF event's own, dotted for nesting.

## Use

Convert them for your SIEM with the Sigma tools you already use. You need a processing pipeline that maps this log source to where your PantherClaw events live, and that is yours to write, as it depends on your backend. Sigma rules run nothing by themselves.

## What was not checked

- `sigma check` has not run on these rules, and they have not been converted with any backend.
- A test reads the rules and evaluates the selection and filter over the samples, which checks the logic and not any conversion.
- `metadata.labels` is an array. Whether `|contains` matches an array element depends on the backend: try the filter on the `alert-high-simulated` sample after you convert.
- The rules are not in the SigmaHQ repository.
