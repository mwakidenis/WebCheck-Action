# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities to the repository maintainer via GitHub Security Advisories or by opening an issue at https://github.com/mwakidenis/WebCheck-Action/issues.

Do not disclose security issues publicly until they have been addressed.

## Security Considerations

This Action sends HTTP and HTTPS requests to websites you specify. Please observe the following:

- Only scan targets you own or have explicit permission to test.
- The Action enforces SSRF protections: loopback, private, link-local, multicast, and other non-routable address ranges are blocked by default unless explicitly enabled for local testing.
- Do not put secrets, authentication tokens, or cookies into report inputs.
- Reports may contain target URLs, response headers, and certificate details. Do not store reports containing sensitive data in public locations.
- TLS certificate verification is enabled by default and is never disabled globally.
- Redirects to prohibited destinations are blocked unless explicitly allowed.

## Self-Contained Design

WebCheck Action performs all checks directly using Node.js built-in modules. It does not depend on the WebCheck-OSINT website, an external API, or any hosted service.
