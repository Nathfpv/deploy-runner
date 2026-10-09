# Nathfpv/deploy-runner

Public open-source deployment utility and Cloudflare OIDC relay configuration.

## Production status (2026-10-09)

- This repository operates the Cloudflare OIDC relay for the project's own relay software.
- **Do not** run private application builds or Hoststar deployments from public hosted jobs in this repository.
- The previous public private-source runner has been disabled in `.github/workflows/deploy.yml` because it executed private project build scripts in a job that later received production credentials and failed to fetch private source (HTTP 401).
- GitHub-hosted public Actions must be used for work related to this repository's own software, not as a free computation service for unrelated private repositories.
- Existing private application deployments remain supported in `Nathfpv/deploy-infra`; their source, secrets, and production backups stay private.
- Keep only the Cloudflare deployment token required by `.github/workflows/deploy-cloudflare-relay.yml`. Remove `HOSTSTAR_FTP_PASSWORD` and `SOURCE_REPO_TOKEN` from *this public repository's* Actions secrets after this change is merged. Do not remove them from private `deploy-infra`.

## Secure migration requirements

A future public deployment interface must be designed for this repository's own eligible software and pass a policy review, an isolated build/deploy credential boundary, private artifact protection, and live end-to-end release/restore tests before it is enabled.

See private `Nathfpv/deploy-infra` issue #12 for the production migration and backup acceptance criteria.
