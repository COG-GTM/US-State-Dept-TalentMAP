# CIO portfolio scanner

A lightweight, zero-deployment tool that scans an entire GitHub organization and generates a static HTML dashboard with a complete portfolio health report. Built around three principles:

- **Observability** — health score, staleness, CI/CD, security scanning, vulnerability alerts, and contributor activity for every repository.
- **Discoverability** — finds every custom agent, bot, and automation running across the portfolio: scheduled GitHub Actions, cron jobs, bot frameworks (slack-bolt, probot, discord), AI/LLM agent dependencies (openai, langchain, anthropic), and external service integrations parsed from env/config/docker-compose files.
- **Auditability** — every finding records the exact GitHub API endpoint or file path it was derived from. The audit trail is viewable per-repo in the dashboard, and the full raw structured data is retained in `portfolio-data.json` with scan timestamps and API call counts.

## Usage

```bash
export GITHUB_TOKEN=ghp_xxxxx
node scanner.js --org <org-name> --output portfolio-data.json
# Then open dashboard.html in a browser
```

No dependencies — uses Node 18+ native fetch. No build step, no server.

> Browsers block `fetch()` of local files when opening `dashboard.html` via `file://`. Either use the file picker shown on load, or serve the folder: `python3 -m http.server 8080` and open `http://localhost:8080/dashboard.html`.

### Options

| Flag | Description |
|------|-------------|
| `--org <name>` | GitHub organization to scan (required) |
| `--output <file>` | Output JSON path (default `portfolio-data.json`) |
| `--limit <n>` | Scan only the N most recently pushed repos (useful for a quick pass) |

## What it checks per repository

| Category | Signals | Source |
|----------|---------|--------|
| Metadata | language, last push, open issues, visibility, archived | `GET /orgs/{org}/repos` |
| Languages | full byte breakdown | `GET /repos/{o}/{r}/languages` |
| Activity | commits + active contributors, last 90 days | `GET /repos/{o}/{r}/commits` |
| Tech stack | `package.json`, `requirements.txt`, `Gemfile`, `go.mod`, `pom.xml` | Contents API |
| CI/CD | `.github/workflows/`, `.circleci/config.yml`, `Jenkinsfile`, `azure-pipelines.yml`, GitLab, Travis | Contents API |
| Auth patterns | `saml`, `oauth`, `jwt`, `passport`, `auth0`, `oidc` in dependency files | Contents API |
| Agents & bots | scheduled (`on: schedule`) GitHub Actions with cron expressions; `cron`, `celery`, `node-cron`, `slack-bolt`, `openai`, `langchain`, `anthropic`, `probot`, `airflow`, and more in dependencies | Contents API |
| External integrations | URLs in `docker-compose.yml`, `.env.example`, setup scripts (e.g. `API_ROOT`, `OBC_URL`, `SSO_LOGIN_URL` patterns) | Contents API |
| Security tooling | Dependabot config, OWASP ZAP / Snyk / Trivy / CodeQL / Semgrep / Sonar references in CI | Contents API |
| Vulnerabilities | open Dependabot alerts | `GET /repos/{o}/{r}/dependabot/alerts` |

## Health score (0–100)

| Component | Points |
|-----------|--------|
| Recency of last commit (≤30d / ≤90d / ≤180d / ≤365d) | 35 / 28 / 18 / 8 |
| CI/CD present | 20 |
| Security scanning (Dependabot + CI security tools) | 8 + 12 |
| Tests present | 15 |
| Dependency manifest present and parseable | 10 |

## Operational notes

- **Rate limiting**: authenticated requests (5000/hr). ~5–15 calls per repo with a 120 ms delay between calls; automatically backs off and resumes if the rate limit is hit.
- **Pagination**: handles orgs with 100+ repos.
- **Error handling**: unreadable repos/files are logged into the repo's `errors` array and the scan continues.
- **Re-runnable**: run weekly/monthly; each output is timestamped for trend tracking.
