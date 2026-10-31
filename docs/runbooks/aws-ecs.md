# Connect Amazon ECS deploys

`pc.aws.ecs` lets an agent deploy one revision of a task definition to an ECS service, and follows the rollout until ECS reports it finished. PantherClaw holds a base access key that can only assume one role. Each request runs in a 15-minute session limited to that one ECS action, and a deploy is limited to that one service. The agent never holds a key.

## Before you start

- **A role for the deploys.** Its policy must allow `ecs:UpdateService` and `ecs:DescribeServices`, and its trust policy must let your base key assume it.
- **The ECS deployment controller.** A service on another controller, such as `CODE_DEPLOY`, is refused with `VERIFIER_UNSUPPORTED`, because its rollout can't be verified.
- **A service that reports a rollout state.** ECS reports none for a service behind a Classic Load Balancer. Deploys to such a service still work, but a person has to confirm each rollout.

## Connect it

Create an `http` connection with package `pc.aws.ecs` and these settings:

- **Base URL:** your region's ECS endpoint, such as `https://ecs.us-east-1.amazonaws.com`.
- **Credential header and scheme:** `Authorization` and `AWS4-HMAC-SHA256`.
- **Allowed hosts:** the ECS host and your STS host.

IAM reads use the separate `pc.aws` package and their own connection, because a connection has one host.

Register the gateway as the connection's fact provider. Without this step every deploy is refused, because PantherClaw can't read the service's deployment controller:

```bash
pclaw fact-provider register --name awsecs --gateway <gateway id> --connection <connection id> \
  --fact aws.ecs.service.controller:object:aws_ecs_service:30s
```

Only a person holding `fact.provider.manage` can register it. Only the gateway that serves the connection may be registered, and only for facts the connection's package names.

Put the secret access key in a file outside the repository, or pipe it in with `--from-file -`. It is never a command-line argument:

```bash
pclaw seal --connection <connection id> --from-file aws.secret \
  --aws-access-key-id <base key id> --aws-role-arn <role ARN> \
  --aws-sts-url https://sts.us-east-1.amazonaws.com --aws-sts-region us-east-1 \
  --aws-region us-east-1 --aws-service ecs
```

Add `--aws-external-id <id>` if the role's trust policy needs one.

This package has no connection test, because a test read must be a GET and ECS has none. A problem with the connection shows up on the first deploy, as a missing `aws.ecs.service.controller` fact. If the gateway log shows `gateway.facts_not_reported`, the gateway isn't registered as the connection's fact provider.

## What a deploy does

1. The agent calls `aws_ecs_deploy_service` with the account, cluster, service and the task definition's full ARN, including its revision. A family name without a revision is refused.
2. PantherClaw reads the service's deployment controller, then decides.
3. After the update, it checks that the service names that revision.
4. It then follows the rollout for up to an hour:

| ECS reports | Result |
|---|---|
| `COMPLETED` | Confirmed, and the deploy reaches the downstream level |
| `IN_PROGRESS` | Still pending |
| `FAILED` | A person decides |
| Deployments of that revision that differ | A person decides |
| No rollout state by the end of the hour | A person decides |

## Known limit

`iam:PassRole` hasn't been tested on real AWS. Each session allows one action only, so if AWS asks for `iam:PassRole` on a task definition with a role, the update is refused. This needs a staging run before you rely on it.
