# Dependabot Granular Policies for the Compliance Framework

OPA/Rego policies designed for the **Granular** operational mode of the [CCF Dependabot Plugin](https://github.com/compliance-framework/plugin-dependabot).

## How this differs from `plugin-dependabot-policies`

The CCF Dependabot plugin supports two operational modes that determine how alerts are fed into the policy engine:

| | `plugin-dependabot-policies` (Bundled) | `plugin-dependabot-granular-policies` (Granular) |
|---|---|---|
| **Input unit** | All alerts for a repository | One alert at a time |
| **Evidence produced** | One evidence set per repository | One evidence set per alert / CVE |
| **Policy focus** | Aggregate counts and trends across alerts | State and attributes of a single alert |
| **Plugin config** | `operational-mode: Bundled` (default) | `operational-mode: Granular` |

### Bundled mode — input shape

Policies receive the full set of alerts for a repository in a single evaluation:

```json
{
  "alerts": [
    {
      "state": "open",
      "security_advisory": {
        "cve_id": "CVE-2024-1234",
        "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
        "cvss": { "score": 9.8 }
      },
      "security_vulnerability": { "severity": "critical" },
      "dependency": {
        "package": { "name": "lodash", "ecosystem": "npm" }
      }
    },
    {
      "state": "open",
      "security_advisory": {
        "cve_id": "CVE-2024-5678",
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cvss": { "score": 7.5 }
      },
      "security_vulnerability": { "severity": "high" },
      "dependency": {
        "package": { "name": "express", "ecosystem": "npm" }
      }
    }
  ],
  "security_team_members": [
    { "login": "alice" },
    { "login": "bob" }
  ]
}
```

Bundled policies can therefore express aggregate rules, for example:

```rego
# Fail if 2 or more critical alerts are open at once
violation[{"id": "too_many_critical_vulnerabilities"}] if {
    open_critical := [a | some a in input.alerts; a.state == "open"; a.security_vulnerability.severity == "critical"]
    count(open_critical) >= 2
}
```

### Granular mode — input shape (this repo)

Each alert is evaluated **independently**. The policy receives a single alert object:

```json
{
  "state": "open",
  "security_advisory": {
    "cve_id": "CVE-2024-1234",
    "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
    "cvss": { "score": 9.8 }
  },
  "security_vulnerability": { "severity": "critical" },
  "dependency": {
    "package": { "name": "lodash", "ecosystem": "npm" }
  }
}
```

A fixed or dismissed alert produces an input like:

```json
{
  "state": "fixed",
  "security_advisory": {
    "cve_id": "CVE-2024-1234",
    "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
    "cvss": { "score": 9.8 }
  },
  "security_vulnerability": { "severity": "critical" },
  "dependency": {
    "package": { "name": "lodash", "ecosystem": "npm" }
  }
}
```

Granular policies therefore check the state of the individual alert:

```rego
# Fail if this specific alert is still open
violation[{"id": "open_cve_alert"}] if {
    input.state == "open"
}
```

## Requirements

Install [opa](https://www.openpolicyagent.org/docs/latest/#running-opa) for testing and building bundles.

## Testing

```shell
opa test policies
```

Or via Make:

```shell
make test
```

## Bundling

```shell
make build
# produces dist/bundle.tar.gz
```

Manual equivalent:

```shell
opa build -b policies -o dist/bundle.tar.gz
```

## Running policies locally

Evaluate a single open alert:

```shell
opa eval -I -b policies -f pretty data.compliance_framework.dependabot_granular_open_alert <<EOF
{
  "state": "open",
  "security_advisory": {
    "cve_id": "CVE-2024-1234",
    "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
    "cvss": { "score": 9.8 }
  },
  "security_vulnerability": { "severity": "critical" },
  "dependency": {
    "package": { "name": "lodash", "ecosystem": "npm" }
  }
}
EOF
```

Expected output for an open alert:

```json
{
  "violation": [{"id": "open_cve_alert"}],
  "title": "CVE-2024-1234 vulnerability is remediated",
  "description": "Each open Dependabot alert is evaluated individually. An open alert for a CVE constitutes a compliance violation that must be remediated."
}
```

Evaluate a fixed alert (no violation expected):

```shell
opa eval -I -b policies -f pretty data.compliance_framework.dependabot_granular_open_alert <<EOF
{
  "state": "fixed",
  "security_advisory": {
    "cve_id": "CVE-2024-1234",
    "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
    "cvss": { "score": 9.8 }
  },
  "security_vulnerability": { "severity": "critical" },
  "dependency": {
    "package": { "name": "lodash", "ecosystem": "npm" }
  }
}
EOF
```

## Writing policies

Policies are written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) under the `compliance_framework` package.

The input document is always a **single** GitHub Dependabot alert object.

```rego
package compliance_framework.my_custom_rule

import future.keywords.in

violation[{"id": "open_cve_alert"}] if {
    input.state == "open"
}

risk_templates := [{
    "name": "open_cve_vulnerability",
    "title": "{{ .cve_id }}: {{ .severity }} severity in {{ .package_name }}",
    "statement": "{{ .cve_id }} affects {{ .package_name }} ({{ .ecosystem }}) in repository {{ .repository }}.",
    "likelihood_hint": "{{ .severity }}",
    "impact_hint": "{{ .impact }}",
    "violation_ids": ["open_cve_alert"],
    "dedupe_label_keys": ["repository", "organization", "cve_id"],
}]

title := "CVE vulnerability is remediated"
description := "Each open Dependabot alert is evaluated individually."
```

### Available input fields

| Field | Type | Description |
|---|---|---|
| `input.state` | string | Alert state: `open`, `fixed`, `dismissed`, `auto_dismissed` |
| `input.security_advisory.cve_id` | string | CVE identifier (may be empty) |
| `input.security_advisory.ghsa_id` | string | GitHub Security Advisory identifier |
| `input.security_advisory.cvss.score` | number | CVSS numeric score |
| `input.security_vulnerability.severity` | string | `critical`, `high`, `medium`, or `low` |
| `input.dependency.package.name` | string | Affected package name |
| `input.dependency.package.ecosystem` | string | Package ecosystem (`npm`, `go`, `pip`, etc.) |
