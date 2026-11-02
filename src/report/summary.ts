export interface SummaryOptions {
  report: import('../config').ScanReport;
  config: import('../config').ActionConfig;
}

function escapeMarkdown(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/`/g, '\\`')
    .replace(/\*/g, '\\*')
    .replace(/_/g, '\\_')
    .replace(/\{/g, '\\{')
    .replace(/\}/g, '\\}')
    .replace(/\[/g, '\\[')
    .replace(/\]/g, '\\]')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)')
    .replace(/#/g, '\\#')
    .replace(/>/g, '\\>')
    .replace(/!/g, '\\!')
    .replace(/\r\n/g, ' ')
    .replace(/\n/g, ' ')
    .replace(/\r/g, ' ');
}

function escapeWorkflowCommand(value: string): string {
  // Neutralize workflow-command injection sequences (::) while preserving
  // normal URL colons so targets remain readable.
  return escapeMarkdown(value).replace(/::/g, '\\:\\:');
}

function statusBadge(status: 'passed' | 'failed'): string {
  return status === 'passed' ? '&#x2705; Passed' : '&#x274c; Failed';
}

function yesNo(value: boolean): string {
  return value ? 'Yes' : 'No';
}

export function generateSummary(options: SummaryOptions): string {
  const { report } = options;
  const lines: string[] = [];

  lines.push('# WebCheck Action Report');
  lines.push('');
  lines.push(`**Tool:** ${escapeMarkdown(report.tool)} ${escapeMarkdown(report.version)}`);
  lines.push(`**Target:** ${escapeWorkflowCommand(report.target)}`);
  lines.push(`**Timestamp:** ${escapeMarkdown(report.timestamp)}`);
  lines.push(`**Overall:** ${statusBadge(report.overall)}`);
  lines.push('');

  // DNS section
  lines.push('## DNS Resolution');
  lines.push('');
  lines.push(`- Resolved: ${yesNo(report.dns.resolved)}`);
  if (report.dns.addresses.length > 0) {
    lines.push(`- Addresses: ${report.dns.addresses.join(', ')}`);
    lines.push(`- Address families: ${report.dns.families.join(', ')}`);
  }
  if (report.dns.error) {
    lines.push(`- Error: ${escapeMarkdown(report.dns.error)}`);
  }
  lines.push('');

  // HTTP section
  lines.push('## HTTP');
  lines.push('');
  lines.push(`- Status code: ${report.http.statusCode ?? 'N/A'}`);
  lines.push(`- Status message: ${escapeMarkdown(report.http.statusMessage ?? 'N/A')}`);
  lines.push(`- Final URL: ${escapeWorkflowCommand(report.http.finalURL ?? 'N/A')}`);
  lines.push(`- Redirect count: ${report.http.redirectCount}`);
  lines.push(`- Response time (ms): ${report.http.responseTimeMs ?? 'N/A'}`);
  lines.push(`- Connect time (ms): ${report.http.connectTimeMs ?? 'N/A'}`);
  lines.push(`- Transport error: ${yesNo(report.http.transportError)}`);
  lines.push(`- Body size (bytes): ${report.http.bodySize}`);
  if (report.http.userAgent) {
    lines.push(`- User-Agent: ${escapeMarkdown(report.http.userAgent)}`);
  }
  if (report.http.error) {
    lines.push(`- Error: ${escapeMarkdown(report.http.error)}`);
  }
  if (report.http.redirectChain.length > 0) {
    lines.push(`- Redirect chain: ${report.http.redirectChain.map((u) => escapeWorkflowCommand(u)).join(' &#8594; ')}`);
  }
  lines.push('');

  // Performance section
  lines.push('## Performance');
  lines.push('');
  lines.push(`- Response time (ms): ${report.performance.responseTimeMs ?? 'N/A'}`);
  lines.push(`- Connect time (ms): ${report.performance.connectTimeMs ?? 'N/A'}`);
  lines.push(`- Threshold (ms): ${report.performance.thresholdMs ?? 'N/A'}`);
  lines.push(`- Within threshold: ${yesNo(report.performance.withinThreshold ?? false)}`);
  if (report.performance.error) {
    lines.push(`- Error: ${escapeMarkdown(report.performance.error)}`);
  }
  lines.push('');

  // TLS section
  lines.push('## TLS / Certificate');
  lines.push('');
  lines.push(`- TLS enabled: ${yesNo(report.tls.enabled)}`);
  lines.push(`- Insecure mode: ${yesNo(report.tls.insecure)}`);
  if (report.tls.enabled) {
    lines.push(`- Hostname mismatch: ${yesNo(report.tls.hostnameMismatch)}`);
    if (report.tls.handshakeError) {
      lines.push(`- Handshake error: ${escapeMarkdown(report.tls.handshakeError)}`);
    }
    if (report.tls.certificate) {
      const cert = report.tls.certificate;
      lines.push(`- Certificate authorized: ${yesNo(cert.authorized)}`);
      if (cert.authorizationError) {
        lines.push(`- Authorization error: ${escapeMarkdown(cert.authorizationError)}`);
      }
      if (cert.tlsVersion) {
        lines.push(`- TLS version: ${escapeMarkdown(cert.tlsVersion)}`);
      }
      if (cert.cipher) {
        lines.push(`- TLS cipher: ${escapeMarkdown(cert.cipher)}`);
      }
      if (cert.subject) {
        const cn = cert.subject['CN'] ?? cert.subject['commonName'] ?? 'N/A';
        lines.push(`- Certificate subject CN: ${escapeMarkdown(cn)}`);
      }
      if (cert.issuer) {
        const org = cert.issuer['O'] ?? cert.issuer['organizationName'] ?? 'N/A';
        lines.push(`- Certificate issuer: ${escapeMarkdown(org)}`);
      }
      lines.push(`- Valid from: ${escapeMarkdown(cert.validFrom ?? 'N/A')}`);
      lines.push(`- Valid to: ${escapeMarkdown(cert.validTo ?? 'N/A')}`);
      lines.push(`- Days remaining: ${cert.daysRemaining ?? 'N/A'}`);
      lines.push(`- Fingerprint: ${escapeMarkdown(cert.fingerprint ?? 'N/A')}`);
    }
    if (report.tls.error) {
      lines.push(`- TLS error: ${escapeMarkdown(report.tls.error)}`);
    }
  }
  lines.push('');

  // Security headers section
  lines.push('## Security Headers');
  lines.push('');
  if (report.headers.headers.length === 0) {
    lines.push('No security headers evaluated.');
  } else {
    lines.push('| Header | Required | Present | Status | Value |');
    lines.push('|---|---|---|---|---|');
    for (const h of report.headers.headers) {
      const value = h.value ? escapeMarkdown(h.value) : '—';
      lines.push(`| ${escapeMarkdown(h.name)} | ${yesNo(h.required)} | ${yesNo(h.present)} | ${h.status} | ${value} |`);
    }
  }
  if (report.headers.missingRequired.length > 0) {
    lines.push('');
    lines.push('### Missing required headers:');
    for (const h of report.headers.missingRequired) {
      lines.push(`- ${escapeMarkdown(h.name)}${h.value ? ` (present: ${escapeMarkdown(h.value)})` : ''}`);
    }
  }
  if (report.headers.error) {
    lines.push(`- Error: ${escapeMarkdown(report.headers.error)}`);
  }
  lines.push('');

  // Routes section
  lines.push('## Routes');
  lines.push('');
  if (report.routes.length === 0) {
    lines.push('No routes configured.');
  } else {
    lines.push('| Route | Status Code | Error | Redirects | Response Time (ms) | Final URL |');
    lines.push('|---|---|---|---|---|---|');
    for (const route of report.routes) {
      lines.push(
        `| ${escapeMarkdown(route.route)} | ${route.statusCode ?? 'N/A'} | ${escapeMarkdown(route.error ?? '—')} | ${route.redirectCount} | ${route.responseTimeMs ?? 'N/A'} | ${escapeWorkflowCommand(route.finalURL ?? '—')} |`
      );
    }
  }
  lines.push('');

  // Findings
  lines.push('## Findings');
  lines.push('');
  if (report.findings.length === 0) {
    lines.push('No findings.');
  } else {
    for (const finding of report.findings) {
      lines.push(`- [${finding.type.toUpperCase()}] ${escapeMarkdown(finding.category)}: ${escapeMarkdown(finding.message)}`);
    }
  }
  lines.push('');

  // Policies
  lines.push('## Failure Policies');
  lines.push('');
  if (report.policyEvaluations.length === 0) {
    lines.push('No policy evaluations.');
  } else {
    lines.push('| Policy | Enabled | Violated | Message |');
    lines.push('|---|---|---|---|');
    for (const p of report.policyEvaluations) {
      lines.push(
        `| ${escapeMarkdown(p.name)} | ${yesNo(p.enabled)} | ${yesNo(p.violated)} | ${escapeMarkdown(p.message ?? '—')} |`
      );
    }
  }
  lines.push('');

  // Baseline comparison section
  if (report.baselineComparison) {
    const bc = report.baselineComparison;
    lines.push('## Baseline Comparison');
    lines.push('');
    if (!bc.compared) {
      lines.push(`Baseline comparison could not be performed: ${bc.error ?? 'unknown error'}`);
    } else {
      lines.push(`- Baseline file: ${escapeWorkflowCommand(bc.baselineFile)}`);
      lines.push(`- New findings (regressions): ${bc.summary.new}`);
      lines.push(`- Resolved findings: ${bc.summary.resolved}`);
      lines.push(`- Unchanged findings: ${bc.summary.unchanged}`);
      lines.push(`- Total findings compared: ${bc.summary.total}`);
      if (bc.newFindings.length > 0) {
        lines.push('');
        lines.push('### New findings (regressions):');
        for (const f of bc.newFindings) {
          lines.push(`- [WARNING] ${escapeMarkdown(f.category)}: ${escapeMarkdown(f.message)}`);
        }
      }
      if (bc.resolvedFindings.length > 0) {
        lines.push('');
        lines.push('### Resolved findings:');
        for (const f of bc.resolvedFindings) {
          lines.push(`- [INFO] ${escapeMarkdown(f.category)}: ${escapeMarkdown(f.message)}`);
        }
      }
    }
    lines.push('');
  }

  // Errors / warnings
  if (report.errors.length > 0) {
    lines.push('## Errors');
    lines.push('');
    for (const err of report.errors) {
      lines.push(`- ${escapeMarkdown(err)}`);
    }
    lines.push('');
  }
  if (report.warnings.length > 0) {
    lines.push('## Warnings');
    lines.push('');
    for (const warn of report.warnings) {
      lines.push(`- ${escapeMarkdown(warn)}`);
    }
    lines.push('');
  }

  lines.push('---');
  lines.push(`Generated by [WebCheck Action](https://github.com/mwakidenis/WebCheck-Action).`);

  return lines.join('\n');
}
