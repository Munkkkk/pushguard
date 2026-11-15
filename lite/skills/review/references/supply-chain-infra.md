# Supply chain and infrastructure

Contents: 1. Dependencies · 2. Lockfiles and install behaviour · 3. GitHub Actions and CI ·
4. Containers · 5. Infrastructure as code · 6. Deployment configuration · 7. Repository hygiene

## 1. Dependencies

For every dependency **added or upgraded** in the diff:

- **Is it the package the author meant?** Typosquats and lookalikes (`lodahs`, `crossenv`,
  `python-dateutils`, scope confusion `@org/pkg` vs `org-pkg`), and names that an AI assistant
  may have invented and an attacker later registered (slopsquatting). A package you do not
  recognize, with a name close to a famous one, deserves a registry lookup. Say when you
  could not verify it.
- **Known vulnerabilities**: run the ecosystem audit when the tool is installed
  (`npm audit --omit=dev`, `pnpm audit --prod`, `pip-audit`, `cargo audit`, `govulncheck`,
  `bundle audit`, `composer audit`). Report an advisory only when the vulnerable package is
  used in production and the vulnerable functionality is plausibly reachable; a ReDoS in a
  build-time dev dependency is noise. Give the fixed version.
- **Source**: dependencies from git URLs, tarball URLs, local paths or a custom registry
  bypass the registry's integrity and review. A private package name without a scope or
  registry pin is exposed to dependency confusion (a public package with the same name wins).
- **Version ranges**: `*`, `latest`, or a missing lockfile make builds irreproducible and
  pull whatever is published next.
- **Downgrades** to a version with known issues, and removal of an `overrides` / `resolutions`
  entry that was pinning a security fix.
- Very new packages or versions (days old), single-maintainer packages with install scripts,
  packages that suddenly add network or filesystem access: mention as a risk, not a verdict.
- Abandoned or deprecated security-relevant libraries (auth, crypto, parsing, sanitizing).

## 2. Lockfiles and install behaviour

- A manifest change without the matching lockfile change (or the reverse) is suspicious.
- In lockfile diffs, look at `resolved` URLs pointing away from the official registry, and
  integrity hashes that changed for an unchanged version.
- Lifecycle scripts: new `preinstall` / `install` / `postinstall` / `prepare` in the project's
  own `package.json`, or `.npmrc` enabling scripts where they were disabled. `setup.py` code
  that runs at install.
- `.npmrc`, `.yarnrc.yml`, `pip.conf`, `.pypirc`: tokens committed, registry changed,
  `strict-ssl=false`, `--trusted-host`, `--extra-index-url` (dependency confusion).
- `curl | sh` style installers in scripts, Dockerfiles or CI: unpinned remote code execution.
- Vendored or copied third-party code, minified blobs and binaries added to the repo: cannot
  be reviewed by reading; ask where they come from.

## 3. GitHub Actions and CI

CI holds deploy keys and registry tokens, so a workflow bug is often a full compromise.

- **Script injection**: `${{ github.event.* }}` values an outsider controls (issue and PR
  titles and bodies, comment bodies, branch names `github.head_ref`, commit messages, author
  names) interpolated directly inside a `run:` block are shell injection. Pass them through
  `env:` and reference `"$VAR"`.
  ```yaml
  - run: echo "${{ github.event.pull_request.title }}"       # vulnerable
  - run: echo "$TITLE"                                        # fixed
    env: { TITLE: "${{ github.event.pull_request.title }}" }
  ```
- **`pull_request_target` and `workflow_run`** run with secrets and a write token in the
  context of the base repository. Checking out and building or running the PR's code there
  (`ref: ${{ github.event.pull_request.head.sha }}` followed by install, build or test) hands
  the secrets to any fork. CRITICAL on public repositories.
- **Permissions**: `permissions:` set to the minimum per job (`contents: read` by default).
  `write-all`, a missing block on older repos, or `id-token: write` / `packages: write` on
  jobs that do not need them.
- **Third-party actions pinned to a full commit SHA.** Tags and branches are mutable and have
  been hijacked. `@main` / `@master` / `@v1` on a non-GitHub-owned action is a MEDIUM finding;
  on a workflow with secrets, treat it seriously.
- **Secrets**: not echoed, not passed to steps that run untrusted code, not exposed to
  PR-triggered workflows from forks, not written to artifacts or caches. `secrets: inherit`
  to reusable workflows passes everything.
- **Self-hosted runners** on public repositories execute fork code on your machine.
- **Artifacts and caches** crossing trust boundaries: a low-privilege PR workflow poisoning a
  cache that a release workflow restores.
- `ACTIONS_ALLOW_UNSECURE_COMMANDS`, `continue-on-error` on security steps, and removal of
  existing checks (tests, lint, scans, required reviews, branch protections as code).
- Deploy steps triggered by events an outsider can cause (issue comments, labels, forks).
- The same questions apply to GitLab CI, CircleCI, Jenkins and others: who can trigger the
  job, what secrets does it see, and what code does it run.

## 4. Containers

- Base image pinned (tag plus digest for strict setups), not `latest`; from a trusted source;
  reasonably current.
- Runs as a non-root `USER`; no `--privileged`, no host network or PID namespace, no Docker
  socket mount, capabilities dropped where the orchestrator allows.
- **No secrets in the image**: `ARG` and `ENV` values, `COPY .env`, keys copied in an early
  layer and deleted later all remain in the layers. Use build-time secret mounts and runtime
  injection. Check `.dockerignore` excludes `.env`, `.git`, keys and local config.
- `ADD` with remote URLs, `curl | sh`, package installs without verification.
- Only required ports exposed; debug ports (9229, 5005) and admin interfaces not published.
- docker-compose / Kubernetes: default or committed passwords, databases published on
  `0.0.0.0`, `hostPath` mounts, `allowPrivilegeEscalation: true`, missing resource limits,
  `Secret` manifests with real values (base64 is not encryption), overly broad RBAC
  (`cluster-admin`, wildcard verbs), `automountServiceAccountToken` where unused.

## 5. Infrastructure as code

Terraform, CloudFormation, Pulumi, Bicep, CDK, serverless configs:

- Network: security groups and firewall rules open to `0.0.0.0/0` or `::/0` on anything but
  public web ports; databases, caches, queues and admin ports reachable from the internet.
- Storage: public buckets and containers, public ACLs, missing block-public-access, object
  listing enabled, no encryption at rest, no versioning on important data.
- IAM: `Action: "*"`, `Resource: "*"`, `Principal: "*"`, wildcard trust policies, long-lived
  access keys created in code, overly broad roles on functions and CI.
- Data stores: `publicly_accessible = true`, encryption or TLS off, default credentials,
  backups and deletion protection disabled.
- Secrets in variables, defaults, outputs or committed state files (`terraform.tfstate`
  contains secrets in plain text; it belongs in a remote encrypted backend).
- Logging and audit trails turned off; API gateways and functions deployed without
  authentication; permissive CORS at the gateway level.

## 6. Deployment configuration

- Framework and platform configs (`next.config.*`, `vercel.json`, `netlify.toml`,
  `nginx.conf`, `Caddyfile`, `fly.toml`, `app.yaml`): rewrites and proxies that expose
  internal services or make the app an open proxy; security headers removed; overly broad
  remote image / fetch patterns (`hostname: '**'`); public source maps; debug or development
  mode in production; relaxed body size limits.
- Environment separation: production credentials used by preview or development deployments;
  preview deployments publicly reachable with production data; previews' wildcard domains in
  CORS or OAuth redirect allow-lists.
- Cron and internal endpoints exposed without a secret.
- Reverse proxy trust: `trust proxy` settings, forwarded headers accepted from anyone.
- Subdomain takeover: DNS or config pointing at a service (bucket, app, page) that the diff removes.

## 7. Repository hygiene

- `.gitignore` covers `.env*`, key material, local databases, build output, IDE and OS files,
  dependency directories. A new ignored-by-convention file committed anyway is worth a note.
- Large binary or archive files, database dumps, exported data, logs and screenshots that may
  contain personal data or internal details.
- Internal hostnames, IPs, employee names, customer data, proprietary documents in a
  repository that is or may become public.
- Git hooks, editor tasks, devcontainer and tool configs that execute commands on open or
  install (`.vscode/tasks.json` with `runOn: folderOpen`, `postCreateCommand`, MCP server
  definitions): they run on every contributor's machine. See also `ai-llm.md`.
- License and attribution problems are out of scope for a security review; skip them.
