package compliance_framework.dependabot_granular_stale_dismissed_alert

ninety_days_ns := 7776000000000000

skip_reason := sprintf("Alert state is %s, this policy only applies to dismissed alerts", [input[0].state]) if {
	input[0].state != "dismissed"
}

violation[{"id": "dismissal_not_reassessed"}] if {
	input[0].state == "dismissed"
	input[0].dismissed_at != null
	is_string(input[0].dismissed_at)
	input[0].dismissed_at != ""
	time.parse_rfc3339_ns(input[0].dismissed_at) < time.now_ns() - ninety_days_ns
}

risk_templates := [{
	"name": "stale_vulnerability_dismissal",
	"title": "{{ .cve_id }}: dismissed {{ .severity }} severity vulnerability needs reassessment",
	"statement": "{{ .cve_id }} affects {{ .package_name }} ({{ .ecosystem }}) in repository {{ .repository }} and was dismissed more than 90 days ago without reassessment.",
	"likelihood_hint": "moderate",
	"impact_hint": "{{ .impact }}",
	"violation_ids": ["dismissal_not_reassessed"],
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

_advisory_id := object.get(object.get(input[0], "security_advisory", {}), "cve_id", "") if {
	object.get(object.get(input[0], "security_advisory", {}), "cve_id", "") != ""
} else := object.get(object.get(input[0], "security_advisory", {}), "ghsa_id", "")

_security_vulnerability := object.get(input[0], "security_vulnerability", {})
_severity := object.get(_security_vulnerability, "severity", "unknown")
_dependency := object.get(input[0], "dependency", {})
_package := object.get(_dependency, "package", {})
_package_name := object.get(_package, "name", "unknown package")
_ecosystem := object.get(_package, "ecosystem", "unknown ecosystem")
_dismissed_at := object.get(input[0], "dismissed_at", "unknown")
one_day_ns := ((24 * 60) * 60) * 1000000000
_dismissal_age_days := floor((time.now_ns() - time.parse_rfc3339_ns(_dismissed_at)) / one_day_ns) if {
	is_string(_dismissed_at)
	_dismissed_at != null
	_dismissed_at != "unknown"
	_dismissed_at != ""
} else := -1
_dismissal_age_text := sprintf("%d days", [_dismissal_age_days]) if {
	_dismissal_age_days >= 0
} else := "unknown"

default title := "Dismissed vulnerability is reassessed"

title := sprintf("%s dismissed vulnerability is reassessed", [_advisory_id]) if {
	_advisory_id != ""
}

description := sprintf("Dependabot alert %s for package %s (%s) is in state dismissed with severity %s and was dismissed at %s. Reassessment SLA is 90 days, and observed dismissal age is %s. Dismissed alerts should be reassessed at least every 90 days.", [_advisory_id, _package_name, _ecosystem, _severity, _dismissed_at, _dismissal_age_text])
