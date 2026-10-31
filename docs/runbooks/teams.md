# Microsoft Teams: agent posts

**Milestone:** M20 (G0 M20 D254, D263, D266, D273, D279). **Audience:** an Org Admin connecting a Teams bot.

Agents post to allowed Teams channels through the `pc.teams` package, decided by the gateway like any other action (HR-524). PantherClaw holds the bot's client secret and mints an access token for each dispatch. The token, never the secret, goes on the request, and the agent holds neither.

## The token endpoint must name your home tenant

Seal the credential with the token endpoint of your own Microsoft Entra tenant:

```text
https://login.microsoftonline.com/<tenant id>/oauth2/v2.0/token
```

The tenant id is a lowercase GUID. The token endpoint is what pins your home tenant, and the agent can never choose it.

The connection's credential header and scheme must be `Authorization` and `Bearer`, and its allowed hosts must include both `login.microsoftonline.com` and the bot's service URL host. Put the client secret in a file outside the repository, or pipe it in with `--from-file -`. It is never a command-line argument:

```bash
pclaw seal --connection <connection id> --from-file bot.secret \
  --oauth-token-url https://login.microsoftonline.com/<tenant id>/oauth2/v2.0/token \
  --oauth-client-id <bot app id> --oauth-scope https://api.botframework.com/.default
```

Sealing refuses any other form, including the multi-tenant `https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token`, because `pc.teams` can't tell an internal channel from an external one without a pinned tenant. Every post would then fail on a missing `teams.channel.external` fact.

Register the gateway as the connection's fact provider. Without this step every post is refused, because PantherClaw can't tell whether the channel is external:

```bash
pclaw fact-provider register --name teams --gateway <gateway id> --connection <connection id> \
  --fact teams.channel.external:object:teams_channel:30s
```

Only a person holding `fact.provider.manage` can register it. Only the gateway that serves the connection may be registered, and only for facts the connection's package names.

## What counts as external

Before each post the gateway reads the channel's members and reports `teams.channel.external`:
- A channel is external when any member belongs to another tenant than your home tenant, or is a guest or anonymous.
- A channel in any other tenant is always external, whatever tenant the agent names.
- A channel that can't be read whole, for example because the bot was never added to it, is a missing fact, never an internal channel.

A post to an external channel predicts the consequence `teams.message.disclose`, which a policy must allow.

## Before the first post

Install the bot in the team, and add it to any shared or private channel it should post to.
