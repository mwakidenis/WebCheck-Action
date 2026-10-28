# Changelog

## [1.0.0] - 2026-10-28

### Added
- Initial release of WebCheck Action.
- HTTP availability and redirect checks with configurable expected status codes and redirect limits.
- HTTPS/TLS certificate inspection (subject, issuer, validity dates, days-to-expiry) with configurable warning/failure thresholds.
- Configurable HTTP security-header checks (strict-transport-security, content-security-policy, x-content-type-options, referrer-policy, permissions-policy).
- Configurable routes with per-route status and error reporting.
- Deterministic JSON reports with tool name, version, timestamp, target, routes, HTTP/TLS/header findings, warnings, errors, and overall result.
- GitHub Actions job summary (Markdown) written to GITHUB_STEP_SUMMARY with proper escaping.
- Configurable failure policies (fail-on-http-error, fail-on-redirect, fail-on-missing-headers, fail-on-tls-error, fail-on-certificate-expiry, fail-on-route-error).
- SSRF protections: blocks loopback, private, link-local, multicast, and non-routable address ranges.
- Redirect destination validation and redirect loop detection.
- Action inputs and outputs per action.yml (result, report-path, findings-count).
- Automated tests (unit and integration) using Vitest, no live third-party targets.
- CI workflows for lint, typecheck, test, and build.
- Bundled Action entry point via @vercel/ncc.
- Examples (basic.yml, advanced.yml).
- README, SECURITY.md, CONTRIBUTING.md, CHANGELOG.md, LICENSE.

### Security
- Certificate verification enabled by default, never disabled globally.
- No eval or shell execution of remote content.
- No secrets logged or transmitted to targets.
- Bounded request timeouts and response sizes.
- Documented TLS checks performed and advanced checks not implemented.
