# Production Security

## Secrets

- Do not store plaintext client secrets in Git.
- Prefer `secret_sha256_hex` in Orionis config.
- Keep plaintext client secrets in a secret manager or local untracked env file.
- Rotate client secrets with overlapping validity when callers cannot switch atomically.

## Signing keys

- Keep private signing keys readable only by the Orionis auth-server process.
- In production, inject the Ed25519 PKCS8 PEM signing key through `private_key_pem_env`.
- Use `/app/var` only for local/demo file-backed deployments that intentionally generate a key on first start.
- Back up production signing keys through your normal secret backup path.
- Publish old and new public keys together during key rotation until every token signed by the old key has expired.

## Token boundaries

- Keep access token TTL short, usually 5 to 15 minutes for service tokens.
- Do not reuse a token minted for one audience against another audience.
- Treat scopes as service permissions, not user permissions.
- Add mTLS or SPIFFE/SPIRE when you need stronger workload identity.

## Runtime hardening

- Put rate limiting and audit logging around `/oauth/token`.
- Run behind TLS in shared environments.
- Keep `log_level` at `info`, `warn`, or `error` outside local debugging.
- Avoid logging tokens, plaintext client secrets, or private key paths.
