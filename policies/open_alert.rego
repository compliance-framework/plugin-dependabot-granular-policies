package compliance_framework.dependabot_granular_open_alert

import future.keywords.in

skip_reason := sprintf("Alert state is %s, this policy only applies to open alerts", [input[0].state]) if {
	input[0].state != "open"
}

violation[{"id": "open_cve_alert"}] if {
	input[0].state == "open"
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

_advisory_id := input[0].security_advisory.cve_id if {
	input[0].security_advisory.cve_id != ""
} else := input[0].security_advisory.ghsa_id

_security_vulnerability := object.get(input[0], "security_vulnerability", {})
_severity := object.get(_security_vulnerability, "severity", "unknown")
_dependency := object.get(input[0], "dependency", {})
_package := object.get(_dependency, "package", {})
_package_name := object.get(_package, "name", "unknown package")
_ecosystem := object.get(_package, "ecosystem", "unknown ecosystem")
_cvss_score := object.get(object.get(object.get(input[0], "security_advisory", {}), "cvss", {}), "score", 0)

default title := "CVE vulnerability is remediated"

title := sprintf("%s vulnerability is remediated", [_advisory_id]) if {
	_advisory_id != ""
}

description := sprintf("Dependabot alert %s for package %s (%s) is in state open with severity %s and CVSS score %.1f. Open alerts constitute a compliance violation that must be remediated.", [_advisory_id, _package_name, _ecosystem, _severity, _cvss_score])
