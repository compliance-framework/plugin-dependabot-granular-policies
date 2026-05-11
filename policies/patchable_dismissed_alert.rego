package compliance_framework.dependabot_granular_patchable_dismissed_alert

import future.keywords.in

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

default title := "Patchable dismissed vulnerability is remediated"

title := sprintf("%s patchable dismissed vulnerability is remediated", [_advisory_id]) if {
	_advisory_id != ""
}

description := "A Dependabot alert with an available patch should not remain dismissed without remediation."
