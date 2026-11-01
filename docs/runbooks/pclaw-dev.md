# `pclaw dev`

**Milestone:** M23 ([G0 M23](../g0/M23.md) D125). **Audience:** developers trying policies and agents on their own machine. This page follows the brief and was written before the command landed; the M23 exit status records any change.

`pclaw dev` runs a development node with the simulators, on loopback only. Everything it does is simulated and proves nothing about a real deployment.

| Command | What it does |
|---|---|
| `pclaw dev up` | Starts the node and the simulators |
| `pclaw dev down` | Stops them, only when the saved process id still matches the started process; otherwise it reports and leaves it, marked unproved |
| `pclaw dev status` | Reports what is running |
| `pclaw dev env` | Prints connection settings, never a secret value |

`up`, `status` and `env` use the same identity check as `down`. A listener that is not yours reads "in use by another process", and `pclaw dev env` will not point at it.
