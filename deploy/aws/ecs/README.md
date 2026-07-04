# AWS ECS Fargate

This directory contains templates for running the published Orionis auth-server image on Amazon ECS Fargate.

The default image is Docker Hub:

```text
stremovskyy/orionis:0.1.2
```

You can replace it with the equivalent GHCR image:

```text
ghcr.io/stremovskyy/orionis:0.1.2
```

## Runtime model

- Fargate task with `awsvpc` networking.
- Public container image, so no `repositoryCredentials` are required.
- `ORIONIS_CONFIG_JSON` comes from AWS Secrets Manager.
- The task writes that secret to `/tmp/orionis.json` and starts `/usr/local/bin/orionis -config /tmp/orionis.json`.
- EFS is mounted at `/app/var` so the Ed25519 signing key persists across task replacements.
- The image runs as `uid=100(orionis)` and `gid=101(orionis)`, so the EFS access point should use POSIX owner `100:101`.

## Required AWS resources

- ECS cluster and service.
- Task execution role with permissions for CloudWatch Logs and `secretsmanager:GetSecretValue` on the Orionis config secret.
- Task role with EFS access point permissions when IAM authorization is enabled.
- CloudWatch log group.
- Secrets Manager secret containing the full Orionis JSON config.
- EFS file system and access point.
- Security group and private subnets for the task.
- Optional load balancer or service discovery target for port `8080`.

## Prepare config

Copy `orionis-config.example.json`, replace all placeholders, and store the full JSON as one Secrets Manager secret:

```bash
aws secretsmanager create-secret \
  --name orionis/config \
  --secret-string file://deploy/aws/ecs/orionis-config.example.json
```

If you update that secret later, force a new ECS deployment so new tasks receive the latest value.

## Create an EFS access point

Create the access point with the same POSIX identity as the container user:

```bash
aws efs create-access-point \
  --file-system-id "$ORIONIS_EFS_FILE_SYSTEM_ID" \
  --posix-user Uid=100,Gid=101 \
  --root-directory "Path=/orionis,CreationInfo={OwnerUid=100,OwnerGid=101,Permissions=750}"
```

Use the returned access point id as `ORIONIS_EFS_ACCESS_POINT_ID`.

## Render and register the task definition

Set placeholders for your account, region, and infrastructure:

```bash
export AWS_REGION=us-east-1
export ORIONIS_EXECUTION_ROLE_ARN="<TASK_EXECUTION_ROLE_ARN>"
export ORIONIS_TASK_ROLE_ARN="<TASK_ROLE_ARN>"
export ORIONIS_CONFIG_SECRET_ARN="<SECRETS_MANAGER_CONFIG_SECRET_ARN>"
export ORIONIS_EFS_FILE_SYSTEM_ID="<EFS_FILE_SYSTEM_ID>"
export ORIONIS_EFS_ACCESS_POINT_ID="<EFS_ACCESS_POINT_ID>"
export ORIONIS_LOG_GROUP="/ecs/orionis-auth"
export ORIONIS_ECS_CLUSTER="<ECS_CLUSTER_NAME>"
export ORIONIS_ECS_SERVICE="orionis-auth"
export ORIONIS_SUBNET_IDS="<SUBNET_ID_1>,<SUBNET_ID_2>"
export ORIONIS_SECURITY_GROUP_IDS="<SECURITY_GROUP_ID>"
```

Render the template without committing environment-specific values:

```bash
python3 - <<'PY' > /tmp/orionis-task-definition.json
import os
from pathlib import Path
from string import Template

template = Template(Path("deploy/aws/ecs/task-definition.template.json").read_text())
print(template.safe_substitute(os.environ))
PY

jq empty /tmp/orionis-task-definition.json
```

Register it:

```bash
aws ecs register-task-definition \
  --cli-input-json file:///tmp/orionis-task-definition.json
```

## Deploy to an ECS service

Create a service from the registered task definition:

```bash
aws ecs create-service \
  --cluster "$ORIONIS_ECS_CLUSTER" \
  --service-name "$ORIONIS_ECS_SERVICE" \
  --task-definition orionis-auth \
  --desired-count 1 \
  --launch-type FARGATE \
  --platform-version LATEST \
  --network-configuration "awsvpcConfiguration={subnets=[$ORIONIS_SUBNET_IDS],securityGroups=[$ORIONIS_SECURITY_GROUP_IDS],assignPublicIp=DISABLED}"
```

Or update an existing service:

```bash
aws ecs update-service \
  --cluster "$ORIONIS_ECS_CLUSTER" \
  --service "$ORIONIS_ECS_SERVICE" \
  --task-definition orionis-auth \
  --force-new-deployment
```

## Verify

Check ECS and container health:

```bash
aws ecs describe-services \
  --cluster "$ORIONIS_ECS_CLUSTER" \
  --services "$ORIONIS_ECS_SERVICE"
```

After the task is reachable through your load balancer or service discovery endpoint:

```bash
curl -fsS https://auth.example.internal/healthz
```

Expected response:

```json
{"service":"orionis-auth","status":"ok"}
```
