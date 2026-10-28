# WebCheck Action

A reusable GitHub Action for website availability, redirect, TLS certificate, security-header, and route checks with JSON reports and configurable CI failure policies.

**Project:** WebCheck Action  
**Owner:** mwakidenis  
**Usage:** `mwakidenis/webcheck-action@v1`  
**Original project:** [WebCheck-OSINT](https://github.com/mwakidenis/WebCheck-OSINT)

WebCheck Action is a focused CI/CD companion, not a replacement for the full WebCheck-OSINT dashboard. It performs checks directly inside GitHub Actions using Node.js built-ins. It does not depend on the WebCheck-OSINT website, a running external API, a hosted database, or private API keys.

## Features

- HTTP availability and redirect checks (status codes, redirect chains, redirect-loop detection, redirect limits).
- HTTPS/TLS certificate inspection (subject, issuer, validity dates, days-to-expiry) with configurable warning and failure thresholds.
- Configurable HTTP security-header checks (strict-transport-security, content-security-policy, x-content-type-options, referrer-policy, permissions-policy).
- Configurable routes with independent per-route status and error reporting.
- Deterministic JSON reports (default `webcheck-report.json`).
- Human-readable GitHub Actions job summary (Markdown).
- Configurable failure policies with sensible defaults.
- SSRF protections (blocks loopback, private, link-local, multicast, and reserved addresses).
- Bounded request timeouts and response sizes.
- No live third-party targets required for tests.

## Requirements

- GitHub Actions (public repositories, `actions/checkout`, `actions/setup-node`).
- Node.js 20 runtime (the `node20` Action runner).
- No Docker, no Python, no extra system packages.

## Installation

Add this to your workflow:

```yaml
steps:
  - name: Check website
    uses: mwakidenis/webcheck-action@v1
    with:
      url: https://example.com
```

This is the target public interface. The `v1` tag is created after a release is published. Until then, you can test locally against this repository (see Local Development).

## Usage

### Basic workflow

```yaml
name: Website checks

on:
  workflow_dispatch:
  push:
    branches: [main]

jobs:
  check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Check website
        uses: mwakidenis/webcheck-action@v1
        with:
          url: https://example.com
```

See `examples/basic.yml`.

### Advanced workflow

```yaml
name: Website checks (advanced)

on:
  workflow_dispatch:
  push:
    branches: [main]

jobs:
  check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Check website
        uses: mwakidenis/webcheck-action@v1
        with:
          url: https://example.com
          routes: |
            /
            /health
            /api/status
          expected-status-codes: 200,204
          timeout: 15
          max-redirects: 10
          required-headers: strict-transport-security, content-security-policy, x-content-type-options, referrer-policy, permissions-policy
          certificate-warning-days: 30
          certificate-failure-days: 7
          fail-on-http-error: true
          fail-on-redirect: false
          fail-on-missing-headers: true
          fail-on-tls-error: true
          fail-on-certificate-expiry: true
          fail-on-route-error: true
          output-file: webcheck-report.json
```

See `examples/advanced.yml`.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `url` | Yes | — | Target URL (http or https). |
| `routes` | No | `/` | Newline-separated paths to check (e.g. `/health`, `/api/status`). |
| `expected-status-codes` | No | `200` | Comma-separated expected HTTP status codes. |
| `timeout` | No | `10` | Request timeout in seconds (1–300). |
| `max-redirects` | No | `10` | Maximum redirects to follow (0–50). |
| `required-headers` | No | `` | Comma-separated required security header names. |
| `certificate-warning-days` | No | `14` | Days until expiry that triggers a warning (0–3650). |
| `certificate-failure-days` | No | `7` | Days until expiry that triggers a failure (0–3650). |
| `fail-on-http-error` | No | `true` | Fail when HTTP status is unexpected or a transport error occurs. |
| `fail-on-redirect` | No | `false` | Fail when any redirect is detected. |
| `fail-on-missing-headers` | No | `false` | Fail when a required security header is missing. |
| `fail-on-tls-error` | No | `true` | Fail when a TLS error is detected. |
| `fail-on-certificate-expiry` | No | `true` | Fail when the certificate is expired or within the failure threshold. |
| `fail-on-route-error` | No | `true` | Fail when any configured route errors. |
| `output-file` | No | `webcheck-report.json` | JSON report destination path. |
| `baseline-file` | No | `` | Optional baseline report path (baseline comparison is documented as a future milestone; not enforced in v1). |

## Outputs

| Output | Description |
|---|---|
| `result` | Overall scan result: `passed` or `failed`. |
| `report-path` | Path to the generated JSON report file. |
| `findings-count` | Total number of findings (warnings + errors). |

## Sample JSON report

```json
{
  "tool": "webcheck-action",
  "version": "1.0.0",
  "timestamp": "2026-10-28T00:00:00.000Z",
  "target": "https://example.com",
  "overall": "passed",
  "http": {
    "statusCode": 200,
    "statusMessage": "OK",
    "finalURL": "https://example.com/",
    "redirectChain": ["https://example.com/"],
    "redirectCount": 0,
    "responseTimeMs": 120,
    "error": null,
    "transportError": false,
    "headers": {},
    "bodySize": 0
  },
  "tls": {
    "enabled": true,
    "certificate": {
      "subject": { "CN": "example.com" },
      "issuer": { "CN": "R3", "O": "Let's Encrypt" },
      "validFrom": "2026-01-01T00:00:00Z",
      "validTo": "2027-01-01T00:00:00Z",
      "daysRemaining": 70,
      "authorized": true
    },
    "hostnameMismatch": false,
    "error": null
  },
  "headers": {
    "headers": [
      { "name": "strict-transport-security", "required": true, "present": true, "status": "present" }
    ],
    "missingRequired": [],
    "error": null
  },
  "routes": [
    { "route": "/", "statusCode": 200, "error": null, "redirectCount": 0 }
  ],
  "findings": [],
  "policyEvaluations": [],
  "errors": [],
  "warnings": []
}
```

## Sample GitHub Actions summary

The Action writes a Markdown summary to `GITHUB_STEP_SUMMARY` with overall status, target, HTTP result, redirect info, TLS certificate status and expiry, security-header findings, route results, warnings, errors, and policy violations. All untrusted values are escaped before writing.

## Exit and failure behavior

- If any enabled failure policy is violated, the Action returns a failing result after producing the report.
- A report-writing failure is surfaced clearly and fails the Action.
- Invalid configuration fails early with a clear error.
- Transport failures (DNS, connection, timeout) are reported as errors and are distinct from HTTP status failures.

## Security

- Certificate verification is enabled by default and is never disabled globally.
- TLS is never assumed secure merely because an HTTPS URL returned a response.
- Loopback (`127.0.0.0/8`, `::1`), private (`10/8`, `172.16/12`, `192.168/16`, IPv6 `fc00::/7`), link-local (`169.254/16`, IPv6 `fe80::/10`), multicast (`224/4`, IPv6 `ff00::/8`), and reserved addresses are blocked unless `allowProhibitedIPs` is explicitly enabled for local testing.
- Redirect destinations are validated; redirects to prohibited addresses are blocked.
- No `eval` or shell execution of remote content. No secrets are logged or transmitted to targets. No page bodies are stored in reports.
- Only scan targets you own or have explicit permission to test.

See `SECURITY.md`.

## TLS checks performed

- Certificate chain and hostname verification (via Node.js `tls` with `rejectUnauthorized`).
- Certificate subject, issuer, validity dates, fingerprint, and days-remaining.
- Expiry warning/failure thresholds.
- Hostname identity checked against certificate Subject Alternative Names (with Common Name fallback).

Not implemented (future): OCSP stapling, CT log verification, cipher-suite grading, TLS version scanning, and external TLS Observatory lookups.

## Local development on Windows 11

1. Install Node.js (LTS) and Git.
2. Clone the repository.
3. Open PowerShell (run as Administrator if execution policy blocks scripts) or use Command Prompt.
4. Install dependencies: `npm ci`
5. Run lint: `npm run lint`
6. Run type check: `npm run typecheck`
7. Run tests: `npm test`
8. Build the bundle: `npm run build` (produces `dist/index.js`)

If PowerShell execution policy blocks `npm`, run `cmd /c "npm ..."` or set the execution policy:
`Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

## Testing and building

- `npm ci` — install dependencies reproducibly from `package-lock.json`.
- `npm run lint` — ESLint.
- `npm run typecheck` — `tsc --noEmit`.
- `npm test` — Vitest unit and integration tests (local test server only; no live third-party targets).
- `npm run build` — bundle `dist/index.js` with `@vercel/ncc`.

## Versioning and releases

1. Update `version` in `package.json` and `CHANGELOG.md`.
2. Commit changes with a message starting with `chore:`.
3. Create and push a Git tag, e.g. `git tag v1.0.0 && git push origin v1.0.0`.
4. Create a GitHub Release from the tag.
5. Consumers reference `mwakidenis/webcheck-action@v1`.

The bundled `dist/index.js` must be committed with the release so consumers do not need `npm install`.

## Contribution guidelines

See `CONTRIBUTING.md`. All changes should be accompanied by tests and pass `npm run lint`, `npm run typecheck`, `npm test`, and `npm run build`.

## License

MIT License. See `LICENSE`.

## Funding

Support the maintainer: https://github.com/sponsors/mwakidenis

## Topics

github-actions, typescript, nodejs, website-monitoring, tls, security-headers, ci-cd, web-security, devtools
