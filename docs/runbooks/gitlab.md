# GitLab: merges and the deployments they start

**Milestone:** M20 (G0 M20 D254, D258, D287, D294). **Audience:** an Org Admin connecting GitLab for agents through `pc.gitlab`.

`pc.gitlab` lets an agent read and merge merge requests. The gateway holds the access token, bound to the connection's GitLab host. The agent never sees it (HR-521).

## What a merge's deployment means

A merge can start a deployment, so `pc.gitlab` treats the deployment as a consequence of the merge (T-229). Before each merge the gateway reads the project's environments, stopped ones included, because a deploying job restarts a stopped environment.

| The project | The head pipeline | What happens |
|---|---|---|
| has environments | passed at the head | The deployment is predicted for each environment. The grant must cover `gitlab.deployment.trigger`, and a policy or grant can require a release approver. |
| has environments | anything else | The consequence is unknown and the merge is held (`CONSEQUENCE_UNKNOWN`). |
| has none, and uses a custom CI configuration path or Auto DevOps | any | The consequence is unknown and the merge is held. |
| has none, and `.gitlab-ci.yml` at the head mentions `environment` or `include`, has a double-quoted string with a backslash, or could not be read | any | The consequence is unknown and the merge is held. |
| has none, and no `.gitlab-ci.yml` at the head, or one that does none of that | any | No consequence. The check reads the source head only, so a deploy job on the target branch that is not at the head is not seen. |

The check of `.gitlab-ci.yml` is a text check, not a parse, so a comment that mentions either word, or a script with an escape in a double-quoted string, also holds the merge.

After a merge, each deployment is verified as its own transaction from GitLab's record of the merge commit. The merge stays downstream `PENDING` until then.

## What is not predicted or verified

- **A new environment name in a project that already has others is not predicted.** The consequence names only environments that exist before the merge. To cover one, create the environment in GitLab before the merge.
- **A compliance pipeline cannot be read.** A project with no environment can deploy through one without being predicted. Create its environments in GitLab first.
- **The token must be able to see the project's CI settings.** If GitLab's project answer leaves out `ci_config_path` or `auto_devops_enabled`, merges into a project with no environment are held. Give the token enough access to see them, or create the project's environments first.
- **Every environment is predicted, including ones the branch never deploys to.** Those end with no deployment, and a person decides.
- **A deployment of the commit by anyone counts.** GitLab has no reserved deployer to check against.
- **A fast-forward merge names no merge commit**, so the deployments it starts stay `NOT_VERIFIABLE`.
- **A token must be able to read the repository.** The gateway treats a 404 for `.gitlab-ci.yml` as no file, so use a token that can read the repository, or the check cannot see the file.
