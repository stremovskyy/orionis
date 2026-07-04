# AWS ECS Fargate

This directory contains templates for running the published Orionis auth-server image on Amazon ECS Fargate.

The default image is Docker Hub:

```text
stremovskyy/orionis:0.1.3
```

You can replace it with the equivalent GHCR image:

```text
ghcr.io/stremovskyy/orionis:0.1.3
```

## Runtime model

- Fargate task with `awsvpc` networking.
- Public container image, so no `repositoryCredentials` are required.
- `ORIONIS_CONFIG_JSON` comes from AWS Secrets Manager.
- `ORIONIS_SIGNING_KEY_PEM` comes from AWS Secrets Manager.
- The task writes that secret to `/tmp/orionis.json` and starts `/usr/local/bin/orionis -config /tmp/orionis.json`.
- The Orionis process reads the Ed25519 signing key from `ORIONIS_SIGNING_KEY_PEM`; it does not use an AWS SDK or write the key to `/app/var`.

## Required AWS resources

- ECS cluster and service.
- Task execution role with permissions for CloudWatch Logs and `secretsmanager:GetSecretValue` on the Orionis config and signing-key secrets.
- CloudWatch log group.
- Secrets Manager secret containing the full Orionis JSON config.
- Secrets Manager secret containing the Ed25519 PKCS8 PEM signing key.
- Security group and private subnets for the task.
- Optional load balancer or service discovery target for port `8080`.

## Prepare config

Create the Ed25519 signing key as PKCS8 PEM and store it in Secrets Manager:

```bash
openssl genpkey -algorithm ED25519 > /tmp/orionis-ed25519.pem

aws secretsmanager create-secret \
  --name orionis/signing-key \
  --secret-string file:///tmp/orionis-ed25519.pem
```

Copy `orionis-config.example.json`, replace placeholders, and store the full JSON as the config secret.
The example config uses `key.private_key_pem_env: "ORIONIS_SIGNING_KEY_PEM"`:

```bash
aws secretsmanager create-secret \
  --name orionis/config \
  --secret-string file://deploy/aws/ecs/orionis-config.example.json
```

If you update either secret later, force a new ECS deployment so new tasks receive the latest value.

## IAM permissions

Grant the task execution role access to both the config secret and the signing-key secret:

```bash
aws iam put-role-policy \
  --role-name "$ORIONIS_EXECUTION_ROLE_NAME" \
  --policy-name OrionisRuntimeSecretsRead \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": [
        "'"$ORIONIS_CONFIG_SECRET_ARN"'",
        "'"$ORIONIS_SIGNING_KEY_SECRET_ARN"'"
      ]
    }]
  }'
```

## Render and register the task definition

Set placeholders for your account, region, and infrastructure:

```bash
export AWS_REGION=us-east-1
export ORIONIS_EXECUTION_ROLE_ARN="<TASK_EXECUTION_ROLE_ARN>"
export ORIONIS_EXECUTION_ROLE_NAME="<TASK_EXECUTION_ROLE_NAME>"
export ORIONIS_TASK_ROLE_ARN="<TASK_ROLE_ARN>"
export ORIONIS_CONFIG_SECRET_ARN="<SECRETS_MANAGER_CONFIG_SECRET_ARN>"
export ORIONIS_SIGNING_KEY_SECRET_ARN="<SECRETS_MANAGER_SIGNING_KEY_SECRET_ARN>"
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
