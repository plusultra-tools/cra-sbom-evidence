# Security Policy

## Reporting a vulnerability

Report vulnerabilities to **plusultra.dev@proton.me** within 24h per our own CRA
Article 14 commitment :)

We will acknowledge receipt within 24 hours, provide an initial assessment
within 72 hours, and aim for a fix within 14 days from a corrective measure
being available — mirroring the CRA Article 14(1)/(2)/(3) timeline this tool
itself helps you implement.

## Supported versions

`0.1.x` — current alpha; security fixes only on `main`.

## Coordinated vulnerability disclosure (CVD) policy

Per CRA Annex I Part II point (5), this project operates a CVD policy:

1. Reporter sends details to plusultra.dev@proton.me with PGP optional.
2. We confirm reproduction and triage within 72h.
3. Embargo period proposed by reporter; default 90 days.
4. Joint advisory at release, with credit unless reporter declines.
5. CVE assigned via MITRE if applicable.

## Scope

In scope:
- The `cra-sbom` CLI and its Python modules.
- The verbatim CRA clause data files (integrity / tampering reports).
- The evidence-pack generation logic.

Out of scope:
- Third-party SBOM/VEX inputs (file at the upstream tool: anchore/syft,
  aquasecurity/trivy, etc.).
- The EUR-Lex source URLs themselves.
