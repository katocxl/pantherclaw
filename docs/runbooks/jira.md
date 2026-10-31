# Connect Jira

**Milestone:** M20 (G0 M20 D254, D275). **Audience:** an Org Admin connecting Jira for agents through `pc.jira`.

`pc.jira` lets an agent read, create, comment on and move Jira issues. The gateway holds the credential, bound to the connection's Jira site, and the agent never sees it (HR-522).

## 1. Create the credential

Create an Atlassian API token for the account the agents will act as. That account needs to browse the projects, and to create, comment on and transition issues in them.

The credential is the base64 of `email:token`. Put `email:token` in a file outside the repository, then encode it, so the token never appears on a command line:

```bash
base64 -w0 jira.plain > jira.secret
```

## 2. Connect it

Use your Jira site, cloud or self-managed, as the base URL. That host is the only one the credential is bound to. The credential pattern is weak, so this binding is what protects it.

```bash
pclaw connection create jira --kind http --gateway <gateway id> --package pc.jira --base-url https://<your site>.atlassian.net \
  --access pantherclaw_held --header Authorization --scheme Basic --default-mode enforce
pclaw seal --connection <connection id> --from-file jira.secret --fingerprint <broker key fingerprint>
```

Then delete both files.

## 3. Register the gateway as the connection's fact provider

Without this step no write goes through, because PantherClaw can't tell whether the project is customer-visible. Issues and new issues use separate facts, because one fact is about one target type:

```bash
pclaw fact-provider register --name jira --gateway <gateway id> --connection <connection id> \
  --fact jira.issue.external:object:jira_issue:30s \
  --fact jira.project.external:object:jira_project:30s
```

Only a person holding `fact.provider.manage` can register it. Only the gateway that serves the connection may be registered, and only for facts the connection's package names.

## 4. Test it

```bash
pclaw connection test <connection id>
```

This lists the projects the credential can see. It proves the credential and the host; it doesn't prove the account may write.

## What counts as external

Before every write the gateway reads the project the write lands in:
- A service desk project is external, because its customers read what is written there. A write into one predicts the consequence `jira.issue.disclose`, which a policy must allow (T-226).
- A project that can't be read is a missing fact, never an internal project.
