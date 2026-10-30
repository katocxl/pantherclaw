# Connect GitLab

**Milestone:** M20 (G0 M20 D254, D287, D289). **Audience:** an Org Admin connecting GitLab for agents through `pc.gitlab`.

These are the setup steps. What a merge's deployment means, and what is not predicted, is in `gitlab.md`. The gateway holds the access token, bound to the connection's GitLab host, and the agent never sees it (HR-521).

## 1. Create an access token

Create a personal, project or group access token. It starts with `glpat-`; anything else is refused before a byte is sent.

- It needs the `api` scope, because agents merge through the API.
- Its user or role must be allowed to merge into the target branches.
- It must be able to read the repository. The gateway treats a 404 for `.gitlab-ci.yml` as no file, so a token that can't read the repository hides that file from the deployment check.

Put the token in a file outside the repository, or pipe it in with `--from-file -`. It is never a command-line argument.

## 2. Connect it

Use `https://gitlab.com`, or your self-managed instance's URL, as the base URL. That host is the only one the token is bound to.

```bash
pclaw connection create gitlab --kind http --gateway <gateway id> --package pc.gitlab --base-url https://gitlab.com \
  --access pantherclaw_held --header Authorization --scheme Bearer --default-mode enforce
pclaw seal --connection <connection id> --from-file gitlab.token --fingerprint <broker key fingerprint>
```

Then delete the token file.

## 3. Register the gateway as the connection's fact provider

Without this step no merge goes through, because PantherClaw can't read the merge request's head, approvals, pipeline, branch protection or deployments, and it never guesses:

```bash
pclaw fact-provider register --name gitlab --gateway <gateway id> --connection <connection id> \
  --fact gitlab.merge_request.head:object:gitlab_merge_request:30s \
  --fact gitlab.merge_request.approvals:object:gitlab_merge_request:30s \
  --fact gitlab.merge_request.pipeline:object:gitlab_merge_request:30s \
  --fact gitlab.branch.protection:object:gitlab_merge_request:30s \
  --fact gitlab.merge_request.deployment:object:gitlab_merge_request:30s
```

Only a person holding `fact.provider.manage` can register it. Only the gateway that serves the connection may be registered, and only for facts the connection's package names.

## 4. Test it

```bash
pclaw connection test <connection id>
```

This lists the projects the token can see. It proves the token and the host; it doesn't prove the token may merge.

Name projects by their numeric id, and merge requests as `<project id>!<iid>`. A request that names a project by its URL-encoded path is refused. A grant for merges must also cover `gitlab.deployment.trigger`.
