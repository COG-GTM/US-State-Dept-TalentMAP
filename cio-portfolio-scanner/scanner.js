#!/usr/bin/env node
/**
 * CIO Portfolio Scanner
 * Scans an entire GitHub organization and produces portfolio-data.json
 * for rendering in dashboard.html.
 *
 * Core principles: observability, discoverability, auditability.
 * Every finding records the API endpoint / file path it came from
 * (the `evidence` array per repo) so the dashboard is fully traceable.
 *
 * Usage:
 *   export GITHUB_TOKEN=ghp_xxxxx
 *   node scanner.js --org <org-name> [--output portfolio-data.json] [--limit N] [--concurrency N]
 */

'use strict';

const fs = require('fs');
const path = require('path');

const API = 'https://api.github.com';

// ---------- CLI ----------
function parseArgs(argv) {
  const args = { output: 'portfolio-data.json', limit: 0, concurrency: 4 };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--org') args.org = argv[++i];
    else if (a === '--output') args.output = argv[++i];
    else if (a === '--limit') args.limit = parseInt(argv[++i], 10) || 0;
    else if (a === '--concurrency') args.concurrency = Math.max(1, parseInt(argv[++i], 10) || 4);
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node scanner.js --org <org-name> [--output portfolio-data.json] [--limit N] [--concurrency N]');
      process.exit(0);
    }
  }
  return args;
}

// ---------- Rate-limited fetch ----------
const DELAY_MS = 120; // ~8 req/s aggregate, well under 5000/hr authenticated limit
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let apiCallCount = 0;

// Shared pacing across all concurrent workers so the aggregate rate stays ~1/DELAY_MS
let nextSlot = 0;
async function throttle() {
  const now = Date.now();
  nextSlot = Math.max(nextSlot + DELAY_MS, now);
  const waitMs = nextSlot - now;
  if (waitMs > 0) await sleep(waitMs);
}

async function gh(url, token, { raw = false, allowError = true } = {}) {
  await throttle();
  apiCallCount++;
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: raw ? 'application/vnd.github.raw+json' : 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'cio-portfolio-scanner',
  };
  let res;
  try {
    res = await fetch(url, { headers });
  } catch (err) {
    if (allowError) return { ok: false, status: 0, data: null, error: String(err) };
    throw err;
  }
  if (res.status === 403 || res.status === 429) {
    const remaining = res.headers.get('x-ratelimit-remaining');
    if (remaining === '0') {
      const reset = parseInt(res.headers.get('x-ratelimit-reset') || '0', 10) * 1000;
      const waitMs = Math.max(reset - Date.now(), 5000);
      console.warn(`  rate limit hit; sleeping ${Math.round(waitMs / 1000)}s...`);
      await sleep(waitMs);
      return gh(url, token, { raw, allowError });
    }
  }
  if (!res.ok) {
    if (allowError) return { ok: false, status: res.status, data: null };
    throw new Error(`GitHub API ${res.status} for ${url}`);
  }
  const data = raw ? await res.text() : await res.json();
  return { ok: true, status: res.status, data };
}

async function ghPaginated(urlBase, token) {
  const all = [];
  let page = 1;
  for (;;) {
    const sep = urlBase.includes('?') ? '&' : '?';
    const { ok, data, status } = await gh(`${urlBase}${sep}per_page=100&page=${page}`, token);
    if (!ok) {
      if (page === 1) throw new Error(`GitHub API ${status} for ${urlBase}`);
      break;
    }
    if (!Array.isArray(data) || data.length === 0) break;
    all.push(...data);
    if (data.length < 100) break;
    page++;
  }
  return all;
}

// ---------- Detection helpers ----------
const DEP_MANIFESTS = ['package.json', 'requirements.txt', 'Gemfile', 'go.mod', 'pom.xml'];
const CI_FILES = ['.circleci/config.yml', 'Jenkinsfile', 'azure-pipelines.yml', '.gitlab-ci.yml', '.travis.yml'];
const AUTH_PATTERNS = ['saml', 'oauth', 'jwt', 'passport', 'auth0', 'oidc', 'openid'];
const AGENT_DEP_PATTERNS = [
  'cron', 'celery', 'node-cron', 'node-schedule', 'slack-bolt', '@slack/bolt', 'slackclient',
  'openai', 'langchain', 'anthropic', 'llama-index', 'llamaindex', 'autogen', 'crewai',
  'semantic-kernel', 'discord.js', 'discord.py', 'telegraf', 'python-telegram-bot', 'botbuilder',
  'probot', 'octokit', 'apscheduler', 'airflow', 'temporalio', 'bullmq', 'agenda',
];
const SECURITY_CI_PATTERNS = ['zap', 'owasp', 'snyk', 'trivy', 'bandit', 'semgrep', 'codeql', 'sonar', 'grype', 'checkov', 'gitleaks', 'trufflehog'];
const ENV_CONFIG_FILES = [
  'docker-compose.yml', 'docker-compose.yaml', '.env.example', '.env.sample',
  'EXAMPLE_setup_environment.sh', 'setup_environment.sh', 'app.json', 'config/env.js',
];
const URL_RE = /https?:\/\/[^\s'"`<>\\)\];,]+/g;
const INTERNAL_URL_FILTER = /(github\.com|githubusercontent|localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|w3\.org|schema|xmlns|opensource\.org|creativecommons|shields\.io|badge|npmjs\.com|yarnpkg|nodejs\.org|python\.org|docker\.com)/i;

function matchPatterns(text, patterns) {
  const lower = text.toLowerCase();
  return patterns.filter((p) => lower.includes(p.toLowerCase()));
}

function extractExternalUrls(text) {
  const urls = text.match(URL_RE) || [];
  return [...new Set(urls.filter((u) => !INTERNAL_URL_FILTER.test(u)))].slice(0, 25);
}

function extractDependencies(filename, content) {
  const deps = [];
  try {
    if (filename === 'package.json') {
      const pkg = JSON.parse(content);
      for (const sec of ['dependencies', 'devDependencies']) {
        for (const [name, ver] of Object.entries(pkg[sec] || {})) deps.push(`${name}@${ver}`);
      }
    } else if (filename === 'requirements.txt') {
      for (const line of content.split('\n')) {
        const t = line.trim();
        if (t && !t.startsWith('#') && !t.startsWith('-')) deps.push(t);
      }
    } else if (filename === 'Gemfile') {
      for (const m of content.matchAll(/^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/gm)) {
        deps.push(m[2] ? `${m[1]}@${m[2]}` : m[1]);
      }
    } else if (filename === 'go.mod') {
      for (const m of content.matchAll(/^\s*([\w.\-/]+\.[\w.\-/]+)\s+(v[\w.\-+]+)/gm)) {
        deps.push(`${m[1]}@${m[2]}`);
      }
    } else if (filename === 'pom.xml') {
      for (const m of content.matchAll(/<artifactId>([^<]+)<\/artifactId>/g)) deps.push(m[1]);
    }
  } catch {
    /* unparseable manifest — skip */
  }
  return deps;
}

function computeHealthScore(r) {
  let score = 0;
  // Staleness (0-35)
  const days = r.daysSinceLastPush;
  if (days <= 30) score += 35;
  else if (days <= 90) score += 28;
  else if (days <= 180) score += 18;
  else if (days <= 365) score += 8;
  // CI presence (0-20)
  if (r.ci.hasCI) score += 20;
  // Security scanning (0-20)
  if (r.security.hasDependabotConfig) score += 8;
  if (r.security.ciSecurityTools.length > 0) score += 12;
  // Tests (0-15)
  if (r.hasTests) score += 15;
  // Dependency age heuristic (0-10): manifest present and parseable
  if (r.dependencies.length > 0) score += 10;
  else if (r.manifestsFound.length > 0) score += 5;
  return Math.min(100, score);
}

// ---------- Per-repo scan ----------
async function scanRepo(org, repo, token) {
  const name = repo.name;
  const evidence = [];
  const errors = [];
  const log = (finding, source) => evidence.push({ finding, source });

  const result = {
    name,
    fullName: repo.full_name,
    description: repo.description || '',
    htmlUrl: repo.html_url,
    primaryLanguage: repo.language || 'Unknown',
    lastPush: repo.pushed_at,
    daysSinceLastPush: repo.pushed_at ? Math.floor((Date.now() - new Date(repo.pushed_at)) / 86400000) : 99999,
    defaultBranch: repo.default_branch,
    openIssues: repo.open_issues_count,
    visibility: repo.visibility,
    archived: repo.archived,
    size: repo.size,
    languages: {},
    activeContributors90d: 0,
    commits90d: 0,
    manifestsFound: [],
    dependencies: [],
    techStack: [],
    ci: { hasCI: false, systems: [], workflows: [], scheduledWorkflows: [] },
    authPatterns: [],
    agents: { detected: false, scheduledActions: [], dependencySignals: [], workflowCronExpressions: [] },
    externalIntegrations: [],
    security: { hasDependabotConfig: false, ciSecurityTools: [], vulnerabilityAlertsEnabled: null, openVulnerabilityAlerts: null },
    hasTests: false,
    healthScore: 0,
    evidence,
    errors,
  };

  const base = `${API}/repos/${org}/${name}`;

  // Languages
  const langs = await gh(`${base}/languages`, token);
  if (langs.ok) {
    result.languages = langs.data;
    log(`languages: ${Object.keys(langs.data).join(', ') || 'none'}`, `GET /repos/${org}/${name}/languages`);
  } else errors.push(`languages: HTTP ${langs.status}`);

  // Commit activity, last 90 days
  const since = new Date(Date.now() - 90 * 86400000).toISOString();
  try {
    const commits = await ghPaginated(`${base}/commits?since=${since}`, token);
    result.commits90d = commits.length;
    const authors = new Set();
    for (const c of commits) {
      const a = (c.author && c.author.login) || (c.commit && c.commit.author && c.commit.author.email);
      if (a) authors.add(a);
    }
    result.activeContributors90d = authors.size;
    log(`${commits.length} commits / ${authors.size} contributors in last 90d`, `GET /repos/${org}/${name}/commits?since=${since}`);
  } catch (e) {
    errors.push(`commits: ${e.message}`);
  }

  // Root listing (used for tests + manifests presence + env files)
  const rootListing = await gh(`${base}/contents/`, token);
  const rootFiles = rootListing.ok ? rootListing.data.map((f) => f.name) : [];
  const rootDirs = rootListing.ok ? rootListing.data.filter((f) => f.type === 'dir').map((f) => f.name) : [];
  if (!rootListing.ok) errors.push(`contents: HTTP ${rootListing.status}`);

  // Tests heuristic
  const testSignals = ['test', 'tests', '__tests__', 'spec', 'specs', 'cypress', 'e2e'];
  result.hasTests = rootDirs.some((d) => testSignals.includes(d.toLowerCase()));

  // Dependency manifests
  let allDepText = '';
  for (const mf of DEP_MANIFESTS) {
    if (rootFiles.length > 0 && !rootFiles.includes(mf)) continue;
    const file = await gh(`${base}/contents/${mf}`, token, { raw: true });
    if (file.ok) {
      result.manifestsFound.push(mf);
      allDepText += `\n${file.data}`;
      const deps = extractDependencies(mf, file.data);
      result.dependencies.push(...deps.map((d) => ({ manifest: mf, dep: d })));
      log(`manifest found with ${deps.length} dependencies`, `GET /repos/${org}/${name}/contents/${mf}`);
    }
  }

  // package.json test script counts toward tests
  if (!result.hasTests && /"test"\s*:\s*"(?!echo)/.test(allDepText)) result.hasTests = true;

  // Tech stack = primary languages + key frameworks
  const stack = new Set(Object.keys(result.languages).slice(0, 4));
  const FRAMEWORKS = ['react', 'angular', 'vue', 'next', 'express', 'django', 'flask', 'fastapi', 'rails', 'spring', 'redux'];
  for (const f of matchPatterns(allDepText, FRAMEWORKS)) stack.add(f);
  result.techStack = [...stack];

  // Auth patterns
  result.authPatterns = matchPatterns(allDepText, AUTH_PATTERNS);
  if (result.authPatterns.length) log(`auth patterns: ${result.authPatterns.join(', ')}`, 'dependency manifests');

  // CI/CD detection
  const workflows = (rootListing.ok && !rootDirs.includes('.github'))
    ? { ok: false }
    : await gh(`${base}/contents/.github/workflows`, token);
  if (workflows.ok && Array.isArray(workflows.data)) {
    result.ci.hasCI = true;
    result.ci.systems.push('GitHub Actions');
    log(`${workflows.data.length} GitHub Actions workflows`, `GET /repos/${org}/${name}/contents/.github/workflows`);
    for (const wf of workflows.data.slice(0, 20)) {
      const wfContent = await gh(`${base}/contents/.github/workflows/${wf.name}`, token, { raw: true });
      if (!wfContent.ok) continue;
      result.ci.workflows.push(wf.name);
      const text = wfContent.data;
      if (/^\s*schedule\s*:/m.test(text) || /on:\s*[\s\S]{0,200}schedule/.test(text)) {
        result.ci.scheduledWorkflows.push(wf.name);
        result.agents.scheduledActions.push(wf.name);
        const crons = [...text.matchAll(/cron\s*:\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
        result.agents.workflowCronExpressions.push(...crons);
        log(`scheduled workflow (cron: ${crons.join(' | ') || 'unparsed'})`, `.github/workflows/${wf.name}`);
      }
      const secTools = matchPatterns(text, SECURITY_CI_PATTERNS);
      for (const t of secTools) {
        if (!result.security.ciSecurityTools.includes(t)) result.security.ciSecurityTools.push(t);
      }
    }
  }
  for (const ciFile of CI_FILES) {
    // Skip API calls for files we already know are absent from the root listing
    if (rootListing.ok) {
      if (ciFile === '.circleci/config.yml') { if (!rootDirs.includes('.circleci')) continue; }
      else if (!rootFiles.includes(ciFile)) continue;
    }
    const file = await gh(`${base}/contents/${ciFile}`, token, { raw: true });
    if (file.ok) {
      result.ci.hasCI = true;
      const sysName = ciFile.includes('circleci') ? 'CircleCI'
        : ciFile === 'Jenkinsfile' ? 'Jenkins'
        : ciFile.includes('azure') ? 'Azure Pipelines'
        : ciFile.includes('gitlab') ? 'GitLab CI' : 'Travis CI';
      if (!result.ci.systems.includes(sysName)) result.ci.systems.push(sysName);
      log(`CI config present`, ciFile);
      const secTools = matchPatterns(file.data, SECURITY_CI_PATTERNS);
      for (const t of secTools) {
        if (!result.security.ciSecurityTools.includes(t)) {
          result.security.ciSecurityTools.push(t);
          log(`security tooling in CI: ${t}`, ciFile);
        }
      }
    }
  }

  // Agent/bot dependency signals
  result.agents.dependencySignals = matchPatterns(allDepText, AGENT_DEP_PATTERNS);
  result.agents.detected =
    result.agents.scheduledActions.length > 0 || result.agents.dependencySignals.length > 0;
  if (result.agents.dependencySignals.length) {
    log(`agent/bot dependency signals: ${result.agents.dependencySignals.join(', ')}`, 'dependency manifests');
  }

  // External integrations (env/config/compose files)
  for (const cf of ENV_CONFIG_FILES) {
    const baseName = cf.split('/').pop();
    if (rootListing.ok) {
      if (!cf.includes('/') && !rootFiles.includes(baseName)) continue;
      if (cf.includes('/') && !rootDirs.includes(cf.split('/')[0])) continue;
    }
    const file = await gh(`${base}/contents/${cf}`, token, { raw: true });
    if (file.ok) {
      const urls = extractExternalUrls(file.data);
      for (const u of urls) {
        if (!result.externalIntegrations.find((x) => x.url === u)) {
          result.externalIntegrations.push({ url: u, source: cf });
        }
      }
      if (urls.length) log(`${urls.length} external URLs`, cf);
    }
  }

  // Dependabot config
  if (rootListing.ok && !rootDirs.includes('.github')) {
    result.security.hasDependabotConfig = false;
  }
  const dependabot = (rootListing.ok && !rootDirs.includes('.github'))
    ? { ok: false }
    : await gh(`${base}/contents/.github/dependabot.yml`, token);
  result.security.hasDependabotConfig = dependabot.ok;
  if (dependabot.ok) log('Dependabot config present', '.github/dependabot.yml');

  // Code quality / security tooling files at root
  if (rootFiles.includes('.codeclimate.yml')) log('CodeClimate config present', '.codeclimate.yml');
  if (rootFiles.includes('.snyk')) {
    if (!result.security.ciSecurityTools.includes('snyk')) result.security.ciSecurityTools.push('snyk');
    log('Snyk policy present', '.snyk');
  }

  // Vulnerability alerts
  const vulnEnabled = await gh(`${base}/vulnerability-alerts`, token, { raw: true });
  result.security.vulnerabilityAlertsEnabled = vulnEnabled.status === 204;
  if (result.security.vulnerabilityAlertsEnabled) {
    const alerts = await gh(`${base}/dependabot/alerts?state=open&per_page=100`, token);
    if (alerts.ok && Array.isArray(alerts.data)) {
      result.security.openVulnerabilityAlerts = alerts.data.length;
      log(`${alerts.data.length} open Dependabot vulnerability alerts`, `GET /repos/${org}/${name}/dependabot/alerts?state=open`);
    }
  }

  result.healthScore = computeHealthScore(result);
  return result;
}

// ---------- Main ----------
async function main() {
  const args = parseArgs(process.argv);
  const token = process.env.GITHUB_TOKEN;
  if (!args.org) {
    console.error('Error: --org <org-name> is required');
    process.exit(1);
  }
  if (!token) {
    console.error('Error: GITHUB_TOKEN environment variable is required');
    process.exit(1);
  }

  console.log(`Scanning organization: ${args.org}`);
  const startedAt = new Date().toISOString();

  let repos = await ghPaginated(`${API}/orgs/${args.org}/repos?type=all&sort=pushed&direction=desc`, token);
  console.log(`Found ${repos.length} repositories`);
  if (args.limit > 0) repos = repos.slice(0, args.limit);

  const results = new Array(repos.length);
  let next = 0;
  let done = 0;
  async function worker() {
    for (;;) {
      const i = next++;
      if (i >= repos.length) return;
      const repo = repos[i];
      try {
        const r = await scanRepo(args.org, repo, token);
        results[i] = r;
        done++;
        console.log(`[${done}/${repos.length}] ${repo.name} health=${r.healthScore} agents=${r.agents.detected ? 'YES' : 'no'} ci=${r.ci.hasCI ? 'yes' : 'no'}`);
      } catch (e) {
        done++;
        console.log(`[${done}/${repos.length}] ${repo.name} ERROR: ${e.message} (skipped)`);
        results[i] = {
          name: repo.name, fullName: repo.full_name, htmlUrl: repo.html_url,
          scanFailed: true, errors: [e.message],
        };
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(args.concurrency, repos.length) }, worker));

  const summary = {
    org: args.org,
    scanStartedAt: startedAt,
    scanCompletedAt: new Date().toISOString(),
    scannerVersion: '1.0.0',
    apiCallCount,
    totalRepos: results.length,
    activeRepos: results.filter((r) => !r.archived && r.daysSinceLastPush <= 180).length,
    staleRepos: results.filter((r) => !r.archived && r.daysSinceLastPush > 180).length,
    archivedRepos: results.filter((r) => r.archived).length,
    reposWithAgents: results.filter((r) => r.agents && r.agents.detected).length,
    reposWithCI: results.filter((r) => r.ci && r.ci.hasCI).length,
    reposWithSecurityScanning: results.filter((r) => r.security && (r.security.hasDependabotConfig || r.security.ciSecurityTools.length > 0)).length,
    totalOpenVulnerabilityAlerts: results.reduce((s, r) => s + ((r.security && r.security.openVulnerabilityAlerts) || 0), 0),
  };

  const output = { summary, repos: results };
  fs.writeFileSync(path.resolve(args.output), JSON.stringify(output, null, 2));
  console.log(`\nDone. ${apiCallCount} API calls. Output written to ${args.output}`);
  console.log(`Open dashboard.html in a browser to view the report.`);
}

main().catch((e) => {
  console.error(`Fatal: ${e.message}`);
  process.exit(1);
});
