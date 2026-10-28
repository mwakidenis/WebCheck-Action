import * as core from '@actions/core';
import { writeFileSync } from 'fs';

import { parseInputs, ActionConfig, ScanReport, PolicyName, PolicyEvaluation } from './config';
import { fetchURL, HTTPRequestOptions } from './http/client';
import { checkTLS } from './checks/tls';
import { checkSecurityHeaders } from './checks/headers';
import { checkRoutes } from './checks/routes';
import { parseAndValidateURL, URLValidationError } from './security/url-validation';
import { checkIP } from './security/ip-validation';
import { buildReport, writeReport } from './report/json';
import { generateSummary } from './report/summary';

function buildClientOptions(config: ActionConfig, servername?: string): HTTPRequestOptions {
  return {
    timeoutMs: config.timeoutSeconds * 1000,
    maxRedirects: config.maxRedirects,
    followRedirects: true,
    rejectUnauthorized: true,
    servername,
  };
}

function evaluateHTTPPolicy(config: ActionConfig, http: ScanReport['http']): PolicyEvaluation {
  let violated = false;
  let message: string | null = null;
  if (http.transportError) {
    violated = true;
    message = `HTTP transport error: ${http.error ?? 'unknown transport error'}`;
  } else if (http.statusCode !== null && !config.expectedStatusCodes.includes(http.statusCode)) {
    violated = true;
    message = `HTTP status ${http.statusCode} is not in expected codes ${config.expectedStatusCodes.join(', ')}`;
  }
  return { name: 'fail-on-http-error', enabled: config.failOnHTTpError, violated, message };
}

function evaluateRedirectPolicy(config: ActionConfig, http: ScanReport['http']): PolicyEvaluation {
  const violated = http.redirectCount > 0;
  return {
    name: 'fail-on-redirect',
    enabled: config.failOnRedirect,
    violated,
    message: violated ? `Redirect detected (${http.redirectCount} redirect(s)).` : null,
  };
}

function evaluateMissingHeadersPolicy(config: ActionConfig, headers: ScanReport['headers']): PolicyEvaluation {
  const violated = headers.missingRequired.length > 0;
  return {
    name: 'fail-on-missing-headers',
    enabled: config.failOnMissingHeaders,
    violated,
    message: violated
      ? `Missing required security headers: ${headers.missingRequired.map((h) => h.name).join(', ')}`
      : null,
  };
}

function evaluateTLSErrorPolicy(tls: ScanReport['tls']): PolicyEvaluation {
  const violated = Boolean(tls.error);
  return {
    name: 'fail-on-tls-error',
    enabled: true, // always evaluated; config flag below
    violated,
    message: tls.error ?? null,
  };
}

function evaluateCertificateExpiryPolicy(
  config: ActionConfig,
  tls: ScanReport['tls']
): PolicyEvaluation {
  const cert = tls.certificate;
  let violated = false;
  let message: string | null = null;
  if (cert) {
    if (cert.daysRemaining !== null && cert.daysRemaining <= config.certificateFailureDays) {
      violated = true;
      message = `Certificate expires in ${cert.daysRemaining} day(s) (failure threshold: ${config.certificateFailureDays}).`;
    } else if (cert.daysRemaining !== null && cert.daysRemaining <= config.certificateWarningDays) {
      // Warning only, not a failure unless within failure days.
    }
  }
  return {
    name: 'fail-on-certificate-expiry',
    enabled: config.failOnCertificateExpiry,
    violated,
    message,
  };
}

function evaluateRouteErrorPolicy(config: ActionConfig, routes: ScanReport['routes']): PolicyEvaluation {
  const violatedRoutes = routes.filter(
    (r) => r.transportError || r.error !== null || (r.statusCode !== null && !config.expectedStatusCodes.includes(r.statusCode))
  );
  const violated = violatedRoutes.length > 0;
  return {
    name: 'fail-on-route-error',
    enabled: config.failOnRouteError,
    violated,
    message: violated
      ? `Route(s) failed: ${violatedRoutes.map((r) => r.route).join(', ')}`
      : null,
  };
}

function isPolicyEnabled(config: ActionConfig, name: PolicyName): boolean {
  switch (name) {
    case 'fail-on-http-error': return config.failOnHTTpError;
    case 'fail-on-redirect': return config.failOnRedirect;
    case 'fail-on-missing-headers': return config.failOnMissingHeaders;
    case 'fail-on-tls-error': return config.failOnTLSError;
    case 'fail-on-certificate-expiry': return config.failOnCertificateExpiry;
    case 'fail-on-route-error': return config.failOnRouteError;
  }
}

async function run(): Promise<void> {
  try {
    const rawInputs: Record<string, string> = {};
    for (const key of [
      'url',
      'routes',
      'expected-status-codes',
      'timeout',
      'max-redirects',
      'required-headers',
      'certificate-warning-days',
      'certificate-failure-days',
      'fail-on-http-error',
      'fail-on-redirect',
      'fail-on-missing-headers',
      'fail-on-tls-error',
      'fail-on-certificate-expiry',
      'fail-on-route-error',
      'output-file',
      'baseline-file',
    ]) {
      rawInputs[key] = core.getInput(key) ?? '';
    }

    let config: ActionConfig;
    try {
      config = parseInputs(rawInputs, { allowProhibitedIPs: false });
    } catch (err) {
      core.setFailed(err instanceof Error ? err.message : 'Invalid configuration.');
      return;
    }

    core.info(`WebCheck Action v${config.version} starting against ${config.url}`);

    // Validate the target URL (SSRF protection).
    let validatedURL: ReturnType<typeof parseAndValidateURL>;
    try {
      validatedURL = parseAndValidateURL(config.url, { allowProhibitedIPs: config.allowProhibitedIPs });
    } catch (err) {
      const msg = err instanceof URLValidationError ? err.message : err instanceof Error ? err.message : 'Invalid URL.';
      core.error(msg);
      core.setFailed(msg);
      return;
    }

    // Re-confirm resolved IP is not prohibited (revalidation at request time).
    let ipCheck: ReturnType<typeof checkIP> | null = null;
    try {
      ipCheck = checkIP(validatedURL.hostname);
      if (ipCheck.isProhibited) {
        const msg = `Target hostname resolves to a prohibited address (${validatedURL.hostname}, category: ${ipCheck.category}).`;
        core.error(msg);
        core.setFailed(msg);
        return;
      }
    } catch {
      // If IP check itself fails, continue; fetchURL will surface DNS errors.
    }

    const report = buildReport(config);
    report.target = config.url;

    const clientOpts = buildClientOptions(config, validatedURL.hostname);

    // 1. HTTP availability check on the target URL.
    const http = await fetchURL(config.url, clientOpts);
    report.http = http;

    if (http.transportError) {
      report.errors.push(`HTTP transport error: ${http.error ?? 'unknown'}`);
    } else if (http.statusCode !== null && !config.expectedStatusCodes.includes(http.statusCode)) {
      report.warnings.push(`HTTP status ${http.statusCode} is not in expected codes ${config.expectedStatusCodes.join(', ')}`);
    }

    // 2. TLS certificate check (HTTPS only).
    if (validatedURL.isSecure) {
      const tls = await checkTLS({
        hostname: validatedURL.hostname,
        port: validatedURL.port,
        servername: validatedURL.hostname,
        timeoutMs: config.timeoutSeconds * 1000,
      });
      report.tls = tls;

      if (tls.error) {
        report.errors.push(`TLS error: ${tls.error}`);
      }
      if (tls.handshakeError) {
        report.warnings.push(`TLS handshake: ${tls.handshakeError}`);
      }
      if (tls.certificate) {
        const cert = tls.certificate;
        if (cert.daysRemaining !== null) {
          if (cert.daysRemaining <= config.certificateFailureDays) {
            report.errors.push(
              `Certificate expires in ${cert.daysRemaining} day(s) (failure threshold: ${config.certificateFailureDays}).`
            );
          } else if (cert.daysRemaining <= config.certificateWarningDays) {
            report.warnings.push(
              `Certificate expires in ${cert.daysRemaining} day(s) (warning threshold: ${config.certificateWarningDays}).`
            );
          }
        }
        if (!cert.authorized) {
          report.warnings.push(`Certificate not authorized: ${cert.authorizationError ?? 'unknown reason'}`);
        }
      }
    } else {
      report.tls.enabled = false;
      report.warnings.push('Target is not HTTPS; TLS certificate checks skipped.');
    }

    // 3. Security header checks (on the final response).
    const requiredHeaders = config.requiredHeaders.filter((h) => h.length > 0);
    const headers = checkSecurityHeaders(http.headers, requiredHeaders);
    report.headers = headers;
    for (const h of headers.missingRequired) {
      report.warnings.push(`Missing required security header: ${h.name}`);
    }
    for (const h of headers.headers) {
      if (h.status === 'misconfigured') {
        report.warnings.push(`Security header may be misconfigured: ${h.name}`);
      }
    }

    // 4. Route checks.
    const allowCrossOriginRedirects = false; // documented option; not exposed as input in v1
    const routes = await checkRoutes({
      baseURL: config.url,
      routes: config.routes,
      timeoutMs: config.timeoutSeconds * 1000,
      maxRedirects: config.maxRedirects,
      rejectUnauthorized: true,
      allowCrossOriginRedirects,
    });
    report.routes = routes;
    for (const route of routes) {
      if (route.transportError || route.error) {
        report.errors.push(`Route ${route.route}: ${route.error ?? 'transport error'}`);
      } else if (route.statusCode !== null && !config.expectedStatusCodes.includes(route.statusCode)) {
        report.warnings.push(`Route ${route.route}: status ${route.statusCode} not expected`);
      }
    }

    // 5. Policy evaluations.
    const policyEvaluations = [
      evaluateHTTPPolicy(config, http),
      evaluateRedirectPolicy(config, http),
      evaluateMissingHeadersPolicy(config, headers),
      evaluateTLSErrorPolicy(report.tls),
      evaluateCertificateExpiryPolicy(config, report.tls),
      evaluateRouteErrorPolicy(config, routes),
    ];
    report.policyEvaluations = policyEvaluations;

    for (const p of policyEvaluations) {
      if (!isPolicyEnabled(config, p.name)) continue;
      if (p.violated && p.message) {
        report.errors.push(`Policy violated: ${p.name} - ${p.message}`);
      }
    }

    // Overall result.
    const anyPolicyViolated = policyEvaluations.some((p) => isPolicyEnabled(config, p.name) && p.violated);
    report.overall = report.errors.length > 0 || anyPolicyViolated ? 'failed' : 'passed';

    // Findings list.
    const findings: ScanReport['findings'] = [];
    for (const err of report.errors) {
      findings.push({ type: 'error', category: 'http', message: err });
    }
    for (const warn of report.warnings) {
      findings.push({ type: 'warning', category: 'http', message: warn });
    }
    report.findings = findings;

    // 6. Write report file.
    try {
      writeReport(report, config.outputFile);
      core.info(`Report written to ${config.outputFile}`);
    } catch (err) {
      const msg = `Failed to write report to ${config.outputFile}: ${err instanceof Error ? err.message : err}`;
      core.error(msg);
      core.setFailed(msg);
      return;
    }

    // 7. GitHub Actions summary.
    const summary = generateSummary({ report, config });
    const summaryPath = process.env.GITHUB_STEP_SUMMARY;
    if (summaryPath) {
      try {
        writeFileSync(summaryPath, summary, 'utf8');
      } catch (err) {
        core.warning(`Failed to write job summary: ${err instanceof Error ? err.message : err}`);
      }
    }

    // 8. Outputs.
    core.setOutput('result', report.overall);
    core.setOutput('report-path', config.outputFile);
    core.setOutput('findings-count', String(report.findings.length));

    core.info(`WebCheck Action completed: ${report.overall}`);

    if (report.overall === 'failed') {
      core.setFailed(`WebCheck Action failed: ${report.errors.length} error(s) found.`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unexpected error.';
    core.error(message);
    core.setFailed(message);
  }
}

run();
