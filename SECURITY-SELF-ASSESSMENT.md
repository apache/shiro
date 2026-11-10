<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->

# Apache Shiro Security Self-Assessment

This is the project's self-assessment of Apache Shiro, following the
[OpenSSF security self-assessment template](https://security-assessments.openssf.org/).
It summarizes, and links to, the authoritative
[security model](https://shiro.apache.org/security-model.html), which defines
the adversaries, guarantees and known non-findings in detail.

## Metadata

| | |
|---|---|
| Assessment created | 2026-11-09 |
| Software | Apache Shiro, <https://github.com/apache/shiro> |
| Security provider | Yes. Shiro is an application security framework. |
| Languages | Java |
| License | Apache License 2.0 |
| Security contact | [security@shiro.apache.org](mailto:security@shiro.apache.org) |
| Security insights | [security-insights.yml](./security-insights.yml) |

## Overview

Apache Shiro is a Java library that adds authentication, authorization,
cryptography and session management to an application. It is embedded in the
application's JVM process; it is not a standalone server or service.

### Background

Applications use Shiro to identify users (`Subject`), verify their credentials
against one or more `Realm`s (LDAP, databases and others), decide whether they may
perform an action (roles and permissions), manage their sessions, and hash or
encrypt data. Integrations exist for servlet and Jakarta EE web containers,
Spring, Guice, CDI and others.

### Actors

| Actor | Description | Trust |
|---|---|---|
| Application code | Code that calls Shiro APIs inside the JVM. | Trusted |
| Operator / administrator | Controls configuration (INI, properties, Spring or Guice wiring), keys, and deployment. | Trusted |
| Realm backing stores | LDAP, databases and other credential or permission sources. | Trusted |
| End user (anonymous or authenticated) | Submits credentials, session identifiers and requests over the network. | **Untrusted** |
| Servlet container / reverse proxy | Normalizes paths, hosts and headers before Shiro sees them. | Trusted to behave as configured |

### Actions

- Authenticate a `Subject` from submitted credentials via configured realms.
- Authorize a `Subject` using role and permission checks, including annotations.
- Create, validate, persist and invalidate sessions, including "remember me" identity.
- Hash passwords and data, and encrypt or decrypt data, through JCA/JCE and BouncyCastle.
- Apply URL-based filter chains to web requests.

### Goals

- Correctly enforce the configured authentication and authorization decisions against
  an unauthenticated or low-privileged network adversary.
- Provide secure defaults for password hashing and session handling, and make secure
  configuration straightforward.
- Do not log plaintext credentials.
- Fix and publicly disclose vulnerabilities through a coordinated process.

### Non-goals

Not provided by Shiro; operators and applications are responsible for these
(see "Known Non-Findings" in the security model):

- CSRF protection, multi-factor authentication, and account lockout.
- Key management infrastructure.
- Defense against code running in the JVM, against administrators with configuration
  access, against local shell access, or against compromised realm data sources.
- Concealing the Shiro version.
- Defending against inconsistent path interpretation by downstream frameworks.

## Self-assessment use

This document is the maintainers' own review. It is not an independent audit,
and it does not replace the security model or an assessment of your deployment.

## Security functions and features

| Function | Critical to security | Notes |
|---|---|---|
| Credential matching and realm coordination | Yes | `CredentialsMatcher`, `AuthenticationStrategy`. |
| Permission and role resolution | Yes | Wildcard permissions and annotations. |
| Session management and fixation prevention | Yes | Pluggable `SessionDAO`; timeouts and validation. |
| Password hashing | Yes | `PasswordService` with Argon2 and BCrypt. |
| Cipher and hash services | Yes | Wrappers over JCA/JCE and BouncyCastle. |
| Web filter chain and `InvalidRequestFilter` | Yes | Relies on the container's path normalization. |
| Remember-me cookie | Security relevant | Weaker guarantees than full authentication, by design. |
| SLF4J security event logging | Supporting | Principals may be logged; credentials are not. |

## Project compliance

Apache Shiro is not claimed to comply with a specific regulatory standard.
The project follows the ASF release and security policies, and self-reports
against the [OSPS Baseline](https://baseline.openssf.org/) using
[security-insights.yml](./security-insights.yml).

## Secure development practices

- **Review:** changes are made by pull request and reviewed by committers.
  Branch rulesets on `main` and release branches prevent deletion and force pushes
  and require a linear history and a passing build.
- **Automated analysis:** CodeQL, GitHub Dependency Review, Dependabot and OpenSSF
  Scorecard run against the repository.
- **Build integrity:** GitHub Actions are pinned to commit SHAs and run with
  least-privilege permissions. Maven and build plugins are pinned, and dependencies
  come from Maven Central. See the dependency policy in [CONTRIBUTING.md](./CONTRIBUTING.md).
- **Testing:** unit and integration tests run in CI on every pull request.
- **Releases:** releases are built by a release manager, signed, voted on by the PMC
  following the [ASF release policy](https://www.apache.org/legal/release-policy.html),
  and published with checksums. Users verify releases as described on the [download page](https://shiro.apache.org/download.html#release_process).
- **Contributions:** contributors license their work under Apache-2.0, and contributions
  either have an ICLA on file with the ASF or acknowledge the license in the pull request template.

## Security issue resolution

- Vulnerabilities are reported privately to
  [security@shiro.apache.org](mailto:security@shiro.apache.org) and handled by the
  PMC under the [ASF security process](https://www.apache.org/security/).
- Reports are acknowledged within the timeframe published on the security reports page, triaged against the security model into the
  dispositions it defines (VALID, VALID-HARDENING, OUT-OF-MODEL, BY-DESIGN,
  KNOWN-NON-FINDING, MODEL-GAP), fixed in a release, then disclosed with a CVE and credit.
- Published advisories: <https://shiro.apache.org/security-reports.html>.
- Supported release lines are listed on the [support page](https://shiro.apache.org/support.html#supported-versions).

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| Authentication bypass via crafted requests or path ambiguity | Filter chains, `InvalidRequestFilter` STRICT mode, application-level checks with Shiro APIs | Downstream frameworks may interpret paths differently; applications must not rely on URL patterns alone. |
| Session fixation and hijacking | Session ID regeneration on login, timeouts, TLS | Session IDs are sensitive; operators must use secure transport and storage. |
| Weak credential storage | Secure default `PasswordService` (Argon2, BCrypt) | Operators can configure weak algorithms. |
| Injection into identity lookups (for example LDAP DN) | Input escaping in realms, fixed through advisories | New realm implementations must escape input. |
| Forged or replayed remember-me cookies | Encryption and server-side age verification | Remember-me is a weaker identity; sensitive actions should require full authentication. |
| Request-derived host or port abuse | Documented host and port configuration, explicit system properties | Depends on reverse proxy and container configuration. |
| Compromised dependency or CI pipeline | Dependabot, Dependency Review, SHA-pinned Actions, signed releases | Third-party supply chain risk remains. |

## Appendix

- Security model: <https://shiro.apache.org/security-model.html>
- Security reports: <https://shiro.apache.org/security-reports.html>
- Architecture: <https://shiro.apache.org/architecture.html>
