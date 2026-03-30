package compliance_framework.dependabot_granular_open_alert

import future.keywords.in

# A single open alert is a compliance violation.
violation[{"id": "open_cve_alert"}] if {
	input.state == "open"
}

risk_templates := [{
	"name": "open_cve_vulnerability",
	"title": "{{ .cve_id }}: {{ .severity }} severity in {{ .package_name }}",
	"statement": "{{ .cve_id }} affects {{ .package_name }} ({{ .ecosystem }}) in repository {{ .repository }}. CVSS score: {{ .cvss_score }}. The alert is currently open and unresolved.",
	"likelihood_hint": "{{ .severity }}",
	"impact_hint": "{{ .impact }}",
	"violation_ids": ["open_cve_alert"],
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

_advisory_id := input.security_advisory.cve_id if {
	input.security_advisory.cve_id != ""
} else := input.security_advisory.ghsa_id

default title := "CVE vulnerability is remediated"

title := sprintf("%s vulnerability is remediated", [_advisory_id]) if {
	_advisory_id != ""
}

description := "Each open Dependabot alert is evaluated individually. An open alert for a CVE constitutes a compliance violation that must be remediated."
