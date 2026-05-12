package compliance_framework.dependabot_granular_patchable_dismissed_alert

import future.keywords.in

skip_reason := sprintf("Alert state is %s, this policy only applies to dismissed alerts", [input[0].state]) if {
	input[0].state != "dismissed"
}

violation[{"id": "patchable_vulnerability_dismissed"}] if {
	input[0].state == "dismissed"
	input[0].dismissed_at != null
	input[0].security_vulnerability.first_patched_version != null
}

risk_templates := [{
	"name": "patchable_vulnerability_dismissed",
	"title": "{{ .cve_id }}: patchable {{ .severity }} severity vulnerability was dismissed",
	"statement": "{{ .cve_id }} affects {{ .package_name }} ({{ .ecosystem }}) in repository {{ .repository }} and has an available patch, but the alert was dismissed rather than remediated.",
	"likelihood_hint": "moderate",
	"impact_hint": "{{ .impact }}",
	"violation_ids": ["patchable_vulnerability_dismissed"],
	"dedupe_label_keys": ["cve_id"],
	"label_schema": [
		{"key": "repository", "description": "GitHub repository affected by the vulnerability"},
		{"key": "organization", "description": "GitHub organization owning the repository"},
		{"key": "cve_id", "description": "CVE or GHSA identifier of the vulnerability"},
		{"key": "package_name", "description": "Name of the affected package"},
		{"key": "ecosystem", "description": "Package ecosystem (go, npm, pip, etc.)"},
		{"key": "severity", "description": "Raw GitHub severity (critical, high, medium, low)"},
		{"key": "impact", "description": "CCF-normalised impact level (critical, high, moderate, low)"},
		{"key": "cvss_score", "description": "CVSS numeric score of the vulnerability"},
	],
}]

_advisory_id := input[0].security_advisory.cve_id if {
	input[0].security_advisory.cve_id != ""
} else := input[0].security_advisory.ghsa_id

_security_vulnerability := object.get(input[0], "security_vulnerability", {})
_severity := object.get(_security_vulnerability, "severity", "unknown")
_first_patched_version := object.get(_security_vulnerability, "first_patched_version", {})
_patched_version := object.get(_first_patched_version, "identifier", "unknown") if {
	is_object(_first_patched_version)
} else := "unknown"
_dependency := object.get(input[0], "dependency", {})
_package := object.get(_dependency, "package", {})
_package_name := object.get(_package, "name", "unknown package")
_ecosystem := object.get(_package, "ecosystem", "unknown ecosystem")

default title := "Patchable dismissed vulnerability is remediated"

title := sprintf("%s patchable dismissed vulnerability is remediated", [_advisory_id]) if {
	_advisory_id != ""
}

description := sprintf("Dependabot alert %s for package %s (%s) is in state dismissed with severity %s and has an available patch at version %s. Patchable vulnerabilities should be remediated rather than dismissed.", [_advisory_id, _package_name, _ecosystem, _severity, _patched_version])
