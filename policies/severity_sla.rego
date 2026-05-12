package compliance_framework.dependabot_granular_severity_sla

one_day_ns := ((24 * 60) * 60) * 1000000000

skip_reason := sprintf("Alert state is %s, this policy only applies to open alerts", [input[0].state]) if {
	input[0].state != "open"
}

reduce_day_ns(ns) := ns if {
	day := time.weekday(ns)
	day != "Sunday"
	day != "Saturday"
}

reduce_day_ns(ns) := working_day_ns if {
	day := time.weekday(ns)
	day == "Sunday"
	working_day_ns := ns - (2 * one_day_ns)
}

reduce_day_ns(ns) := working_day_ns if {
	day := time.weekday(ns)
	day == "Saturday"
	working_day_ns := ns - one_day_ns
}

violation[{"id": "critical_vulnerability_sla_breached"}] if {
	input[0].state == "open"
	input[0].security_vulnerability.severity == "critical"
	is_string(input[0].created_at)
	input[0].created_at != ""
	working_day_now_ns := reduce_day_ns(time.now_ns())
	seven_days_ago := working_day_now_ns - (7 * one_day_ns)
	time.parse_rfc3339_ns(input[0].created_at) < seven_days_ago
}

violation[{"id": "high_vulnerability_sla_breached"}] if {
	input[0].state == "open"
	input[0].security_vulnerability.severity == "high"
	is_string(input[0].created_at)
	input[0].created_at != ""
	working_day_now_ns := reduce_day_ns(time.now_ns())
	two_weeks_ago := working_day_now_ns - (14 * one_day_ns)
	time.parse_rfc3339_ns(input[0].created_at) < two_weeks_ago
}

violation[{"id": "medium_vulnerability_sla_breached"}] if {
	input[0].state == "open"
	input[0].security_vulnerability.severity == "medium"
	is_string(input[0].created_at)
	input[0].created_at != ""
	working_day_now_ns := reduce_day_ns(time.now_ns())
	one_month_ago := working_day_now_ns - (28 * one_day_ns)
	time.parse_rfc3339_ns(input[0].created_at) < one_month_ago
}

violation[{"id": "low_vulnerability_sla_breached"}] if {
	input[0].state == "open"
	input[0].security_vulnerability.severity == "low"
	is_string(input[0].created_at)
	input[0].created_at != ""
	working_day_now_ns := reduce_day_ns(time.now_ns())
	three_months_ago := working_day_now_ns - (84 * one_day_ns)
	time.parse_rfc3339_ns(input[0].created_at) < three_months_ago
}

risk_templates := [
	{
		"name": "critical_vulnerability_sla_breach",
		"title": "{{ .cve_id }}: critical severity vulnerability exceeded remediation SLA",
		"statement": "{{ .cve_id }} affects {{ .package_name }} ({{ .ecosystem }}) in repository {{ .repository }} and has remained open beyond the critical vulnerability remediation SLA.",
		"likelihood_hint": "high",
		"impact_hint": "critical",
		"violation_ids": ["critical_vulnerability_sla_breached"],
		"dedupe_label_keys": ["cve_id"],
		"label_schema": [
			{"key": "repository", "description": "GitHub repository affected by the vulnerability"},
			{"key": "cve_id", "description": "CVE or GHSA identifier of the vulnerability"},
			{"key": "package_name", "description": "Name of the affected package"},
			{"key": "ecosystem", "description": "Package ecosystem (go, npm, pip, etc.)"},
		]
	},
	{
		"name": "high_vulnerability_sla_breach",
		"title": "{{ .cve_id }}: high severity vulnerability exceeded remediation SLA",
		"statement": "{{ .cve_id }} affects {{ .package_name }} ({{ .ecosystem }}) in repository {{ .repository }} and has remained open beyond the high vulnerability remediation SLA.",
		"likelihood_hint": "moderate",
		"impact_hint": "high",
		"violation_ids": ["high_vulnerability_sla_breached"],
		"dedupe_label_keys": ["cve_id"],
		"label_schema": [
			{"key": "repository", "description": "GitHub repository affected by the vulnerability"},
			{"key": "cve_id", "description": "CVE or GHSA identifier of the vulnerability"},
			{"key": "package_name", "description": "Name of the affected package"},
			{"key": "ecosystem", "description": "Package ecosystem (go, npm, pip, etc.)"},
		]
	},
	{
		"name": "medium_vulnerability_sla_breach",
		"title": "{{ .cve_id }}: medium severity vulnerability exceeded remediation SLA",
		"statement": "{{ .cve_id }} affects {{ .package_name }} ({{ .ecosystem }}) in repository {{ .repository }} and has remained open beyond the medium vulnerability remediation SLA.",
		"likelihood_hint": "moderate",
		"impact_hint": "moderate",
		"violation_ids": ["medium_vulnerability_sla_breached"],
		"dedupe_label_keys": ["cve_id"],
		"label_schema": [
			{"key": "repository", "description": "GitHub repository affected by the vulnerability"},
			{"key": "cve_id", "description": "CVE or GHSA identifier of the vulnerability"},
			{"key": "package_name", "description": "Name of the affected package"},
			{"key": "ecosystem", "description": "Package ecosystem (go, npm, pip, etc.)"},
		]
	},
	{
		"name": "low_vulnerability_sla_breach",
		"title": "{{ .cve_id }}: low severity vulnerability exceeded remediation SLA",
		"statement": "{{ .cve_id }} affects {{ .package_name }} ({{ .ecosystem }}) in repository {{ .repository }} and has remained open beyond the low vulnerability remediation SLA.",
		"likelihood_hint": "low",
		"impact_hint": "moderate",
		"violation_ids": ["low_vulnerability_sla_breached"],
		"dedupe_label_keys": ["cve_id"],
		"label_schema": [
			{"key": "repository", "description": "GitHub repository affected by the vulnerability"},
			{"key": "cve_id", "description": "CVE or GHSA identifier of the vulnerability"},
			{"key": "package_name", "description": "Name of the affected package"},
			{"key": "ecosystem", "description": "Package ecosystem (go, npm, pip, etc.)"},
		]
	}
]

_advisory_id := object.get(object.get(input[0], "security_advisory", {}), "cve_id", "") if {
	object.get(object.get(input[0], "security_advisory", {}), "cve_id", "") != ""
} else := object.get(object.get(input[0], "security_advisory", {}), "ghsa_id", "")

_alert := input[0]
_security_vulnerability := object.get(_alert, "security_vulnerability", {})
_severity := object.get(_security_vulnerability, "severity", "unknown")
_dependency := object.get(_alert, "dependency", {})
_package := object.get(_dependency, "package", {})
_package_name := object.get(_package, "name", "unknown package")
_ecosystem := object.get(_package, "ecosystem", "unknown ecosystem")
_state := object.get(_alert, "state", "unknown")
_created_at := object.get(_alert, "created_at", "unknown")
_sla_days := 7 if {
	_severity == "critical"
} else := 14 if {
	_severity == "high"
} else := 28 if {
	_severity == "medium"
} else := 84 if {
	_severity == "low"
} else := 0
_working_day_now_ns := reduce_day_ns(time.now_ns())
_created_age_days := floor((_working_day_now_ns - time.parse_rfc3339_ns(_created_at)) / one_day_ns) if {
	is_string(_created_at)
	_created_at != null
	_created_at != "unknown"
	_created_at != ""
} else := -1
_created_age_text := sprintf("%d days", [_created_age_days]) if {
	_created_age_days >= 0
} else := "unknown"
_sla_deadline_text := "not applicable" if {
	_sla_days == 0
} else := sprintf("%d working days", [_sla_days]) if {
	_created_age_days >= 0
} else := "unknown"

default title := "Vulnerability remediation SLA is met"

title := sprintf("%s vulnerability remediation SLA is met", [_advisory_id]) if {
	_advisory_id != ""
}

description := sprintf("Dependabot alert %s for package %s (%s) is in state %s with severity %s. SLA is %s, created_at is %s, and observed age is %s.", [_advisory_id, _package_name, _ecosystem, _state, _severity, _sla_deadline_text, _created_at, _created_age_text])
