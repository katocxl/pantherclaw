# Runbook — Commands on cloud machines: AWS Systems Manager and Azure Run Command

**Milestone:** M34 ([G0 M34](../g0/M34.md) D993, D993a item 3, D1002; founder decision FQ34-4; HR-525, HR-763; T-348). **Audience:** platform and security teams. **Edition:** Community.

`pc.aws-ssm` lets an agent run shell or PowerShell commands on one Amazon EC2 instance through AWS Systems Manager, and `pc.azure-compute` lets it run a script on one Azure virtual machine through Run Command. Both are irreversible `code.execute` operations: decided per call, shown to an approver in full, and named by no template grant. A grant has to name them.

Both API shapes are taken from the providers' published references and checked only against the simulators until a real account check (R-85).

## AWS packages with extra ARNs

An AWS session is narrowed to exactly one action (HR-525). A write names its resource in the dispatch field `aws_resource`, an ARN template whose references come only from the decision's target, package literals and the connection's AWS account, region and partition, never from a free agent parameter, and with no wildcard.

Some actions need more than one resource. `ssm:SendCommand` is evaluated by IAM on the instance and on the document. A package may then name up to **3 more exact ARNs** in `aws_extra_resources`, under the same rules (founder decision FQ34-4):

- They sit only beside an `aws_resource`; a read (`Resource: "*"`) has none.
- Each is distinct, and none repeats `aws_resource`.
- The session is still **one action**, on exactly those ARNs, in order. Never a wildcard, never a second action.

For `aws.ssm.send_command` on instance `i-0123456789abcdef0` the session policy is:

```json
{"Statement":[{"Action":"ssm:SendCommand","Effect":"Allow","Resource":[
  "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
  "arn:aws:ssm:us-east-1::document/AWS-RunShellScript"]}],"Version":"2012-10-17"}
```

A session that names only one of the two is refused by AWS, so both must be in it. The simulator checks this the same way (it requires every resource the call names).

## pc.aws-ssm

| Operation | Tool | Document | Target |
|---|---|---|---|
| `aws.ssm.send_command` | `aws_ssm_send_command` | `AWS-RunShellScript` | one EC2 instance, `^i-[0-9a-f]{8,17}$` |
| `aws.ssm.send_powershell_command` | `aws_ssm_send_powershell_command` | `AWS-RunPowerShellScript` | one EC2 instance |

- The document is a literal of the package; the agent chooses only the instance and the commands.
- `commands` is a command param, at most 8192 bytes, sent as SSM's `Parameters.commands`. An approval shows it in full beside the instance (HR-034).
- Deduplicated on the instance and the commands; `retry.safe` is false and an unknown outcome is reconciled.
- One instance per call. Hybrid managed nodes (`mi-…`) are not a target.

### Connect it

1. **A role for the commands.** Its policy allows `ssm:SendCommand` on the instances agents may reach and on `arn:aws:ssm:<region>::document/AWS-RunShellScript` (and `AWS-RunPowerShellScript` if used). Its trust policy lets your base key assume it. The session narrows it further for each call.
2. **An `http` connection** with package `pc.aws-ssm`, base URL your region's SSM endpoint (such as `https://ssm.us-east-1.amazonaws.com`), credential header `Authorization` and scheme `AWS4-HMAC-SHA256`, and allowed hosts the SSM host and your STS host.
3. **Seal the credential.** Put the secret access key in a file outside the repository, or pipe it with `--from-file -`; it is never a command-line argument:

```bash
pclaw seal --connection <connection id> --from-file aws.secret \
  --aws-access-key-id <base key id> --aws-role-arn <role ARN> \
  --aws-sts-url https://sts.us-east-1.amazonaws.com --aws-sts-region us-east-1 \
  --aws-region us-east-1 --aws-service ssm
```

Add `--aws-external-id <id>` if the role's trust policy needs one. PantherClaw holds the base key, which signs nothing but one `sts:AssumeRole` per dispatch, for 15 minutes, with the session policy above. The agent never holds a key, and the base key never reaches SSM.

4. **A grant** that names the operation and the instances. No template grants it, so without one every call holds for a person.

### What a call does

The agent calls the tool with `instance_id` and `commands`. PantherClaw decides on the instance and the commands. On an allow it assumes the role with the two-ARN session, and sends `AmazonSSM.SendCommand` with the literal document. The command runs on the instance with the SSM agent's privileges, outside any PantherClaw sandbox; PantherClaw does not see what it does there.

## pc.azure-compute

`azure.vm.run_command` (tool `azure_vm_run_command`) posts to `…/subscriptions/{subscription}/resourceGroups/{group}/providers/Microsoft.Compute/virtualMachines/{vm}/runCommand` on Azure Resource Manager (api-version 2024-07-01).

- Target: the VM, `<subscription id>/<resource group>/<vm name>`.
- `command_id` is a closed enum, `RunShellScript` or `RunPowerShellScript`; `script` is a command param of at most 8192 bytes. An approval shows both beside the VM.
- Deduplicated on the VM, the command id and the script; irreversible.

Connect it with an `http` connection of package `pc.azure-compute`, base URL `https://management.azure.com`, and an `oauth_client` credential for an Entra application with Run Command rights on the VMs agents may reach (scope `https://management.azure.com/.default`). PantherClaw mints a token for each dispatch at the tenant's v2.0 token endpoint; the token, never the secret, is placed on the request.

## Threat map

Both packages are `prevent.cloud_admin_command` (T1651 Cloud Administration Command, surface GATEWAY): every call is decided at the gateway, on its target and commands.

## Simulators and dev seeds

`pantherclaw-sim aws` serves SSM `SendCommand` (and STS `GetCallerIdentity`); `pantherclaw-sim azure` (port 9115) serves Entra tokens and ARM `runCommand`. Nothing runs anywhere. The dev seed's `--aws-ssm-url` and `--azure-url` (with `--gateway-out`) seed the packages and their connections. DEVELOPMENT ONLY.
