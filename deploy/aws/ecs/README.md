# AWS ECS Fargate

This directory contains templates for running the published Orionis auth-server image on Amazon ECS Fargate.

The default image is Docker Hub:

```text
stremovskyy/orionis:0.5.0
```

You can replace it with the equivalent GHCR image:

```text
ghcr.io/stremovskyy/orionis:0.5.0
```

## Runtime model

- Fargate starts `/usr/local/bin/orionis -config aws` directly.
- Confucius v1.4.1 reads the hosted AppConfig JSON once during startup, with a
  30-second deadline. There is no background poller or fallback configuration.
- `AWS_APPCONFIG_APPLICATION`, `AWS_APPCONFIG_ENVIRONMENT`, and
  `AWS_APPCONFIG_PROFILE` must identify the deployed configuration. `AWS_REGION`
  falls back to `AWS_DEFAULT_REGION`, then `eu-central-1`.
- Signing-key PEMs remain in Secrets Manager. ECS injects
  `ORIONIS_SIGNING_KEY_PEM` and, during rotation, `ORIONIS_SIGNING_KEY_PEM_OLD`.
  AppConfig contains only their `private_key_pem_env` references.
- Local JSON configuration with `-config path/to/config.json` remains supported.

## Prepare AppConfig

Create an application, environment, and hosted freeform configuration profile,
following the names used by the other services:

```bash
aws appconfig create-application --name Orionis
aws appconfig create-environment --application-id "$ORIONIS_APPCONFIG_APPLICATION" --name Production
aws appconfig create-configuration-profile \
  --application-id "$ORIONIS_APPCONFIG_APPLICATION" \
  --name main-config --location-uri hosted --type AWS.Freeform
```

Copy `orionis-config.example.json` and replace its placeholders. Store only client
SHA-256 digests, never plaintext credentials. Keep the active and overlapping
signing keys in Secrets Manager as PKCS8 PEM, referenced by environment name in
JSON. For a single signing key, omit the old key from both JSON and the task
secret mappings. For an existing deployment, preserve its issuer, base path,
clients, audiences, scopes, TTL, key IDs, and key secret ARN exactly.

Upload the completed JSON and activate the returned version:

```bash
aws appconfig create-hosted-configuration-version \
  --application-id "$ORIONIS_APPCONFIG_APPLICATION" \
  --configuration-profile-id "$ORIONIS_APPCONFIG_PROFILE" \
  --content-type application/json --content fileb:///tmp/orionis-config.json
aws appconfig start-deployment \
  --application-id "$ORIONIS_APPCONFIG_APPLICATION" \
  --environment-id "$ORIONIS_APPCONFIG_ENVIRONMENT" \
  --configuration-profile-id "$ORIONIS_APPCONFIG_PROFILE" \
  --configuration-version "$ORIONIS_APPCONFIG_VERSION" \
  --deployment-strategy-id AppConfig.AllAtOnce
```

Wait for AppConfig deployment state `COMPLETE` before starting new tasks. Future
configuration changes also require rolling task replacement after deployment.

## IAM permissions

The **task execution role** needs CloudWatch Logs permissions and
`secretsmanager:GetSecretValue` on the signing-key secrets for ECS injection.
The **task role**, used by Confucius inside the container, needs:

```json
{
  "Effect": "Allow",
  "Action": ["appconfig:StartConfigurationSession", "appconfig:GetLatestConfiguration"],
  "Resource": "arn:aws:appconfig:<REGION>:<ACCOUNT>:application/<APP>/environment/<ENV>/configuration/<PROFILE>"
}
```

Keep these runtime permissions on the task role even when it differs from the
execution role. No config secret is injected into the new task.

## Render and register the task definition

Set placeholders for your account, region, and infrastructure:

```bash
export AWS_REGION=us-east-1
export ORIONIS_EXECUTION_ROLE_ARN="<TASK_EXECUTION_ROLE_ARN>"
export ORIONIS_EXECUTION_ROLE_NAME="<TASK_EXECUTION_ROLE_NAME>"
export ORIONIS_TASK_ROLE_ARN="<TASK_ROLE_ARN>"
export ORIONIS_APPCONFIG_APPLICATION="<APPLICATION_ID>"
export ORIONIS_APPCONFIG_ENVIRONMENT="<ENVIRONMENT_ID>"
export ORIONIS_APPCONFIG_PROFILE="<CONFIGURATION_PROFILE_ID>"
export ORIONIS_SIGNING_KEY_SECRET_ARN="<SECRETS_MANAGER_SIGNING_KEY_SECRET_ARN>"
export ORIONIS_OLD_SIGNING_KEY_SECRET_ARN="<SECRETS_MANAGER_OLD_SIGNING_KEY_SECRET_ARN>"
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
  --deployment-configuration 'minimumHealthyPercent=100,maximumPercent=200,deploymentCircuitBreaker={enable=true,rollback=true}' \
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
curl -fsS https://auth.example.internal/readyz
```

Expected response:

```json
{"service":"orionis-auth","status":"ok"}
```

## Migrate and roll back

Before migration, record the old task-definition ARN, image digest, config-secret
version, JWKS, and a successful token/consumer validation. Copy the **active** config
version exactly; do not activate unrelated prepared versions. Preserve signing
key references. Validate the new image/configuration before service replacement.

Use `minimumHealthyPercent=100` and `maximumPercent=200` so ECS starts a new task
while the old task serves requests. Keep the deployment circuit breaker enabled.
Monitor readiness, token issuance, JWT signature/claims, and a safe protected
consumer request throughout replacement. Verify tokens issued before deployment
remain valid after it and confirm the JWKS/key IDs have not changed.

If startup or business-path checks fail, update the service back to the recorded
old task-definition ARN. Retain the old config secret as the rollback source;
do not delete it as part of migration. Do not rotate keys or change client grants
in the configuration-source migration.
