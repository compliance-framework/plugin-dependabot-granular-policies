package compliance_framework.dependabot_granular_severity_sla

one_day_ns := ((24 * 60) * 60) * 1000000000

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
	working_day_now_ns := reduce_day_ns(time.now_ns())
	seven_days_ago := working_day_now_ns - (7 * one_day_ns)
	time.parse_rfc3339_ns(input[0].created_at) < seven_days_ago
}

violation[{"id": "high_vulnerability_sla_breached"}] if {
	input[0].state == "open"
	input[0].security_vulnerability.severity == "high"
	working_day_now_ns := reduce_day_ns(time.now_ns())
	two_weeks_ago := working_day_now_ns - (14 * one_day_ns)
	time.parse_rfc3339_ns(input[0].created_at) < two_weeks_ago
}

violation[{"id": "medium_vulnerability_sla_breached"}] if {
	input[0].state == "open"
	input[0].security_vulnerability.severity == "medium"
	working_day_now_ns := reduce_day_ns(time.now_ns())
	one_month_ago := working_day_now_ns - (28 * one_day_ns)
	time.parse_rfc3339_ns(input[0].created_at) < one_month_ago
}

violation[{"id": "low_vulnerability_sla_breached"}] if {
	input[0].state == "open"
	input[0].security_vulnerability.severity == "low"
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
		"dedupe_label_keys": ["cve_id"]
	},
	{
		"name": "high_vulnerability_sla_breach",
		"title": "{{ .cve_id }}: high severity vulnerability exceeded remediation SLA",
		"statement": "{{ .cve_id }} affects {{ .package_name }} ({{ .ecosystem }}) in repository {{ .repository }} and has remained open beyond the high vulnerability remediation SLA.",
		"likelihood_hint": "moderate",
		"impact_hint": "high",
		"violation_ids": ["high_vulnerability_sla_breached"],
		"dedupe_label_keys": ["cve_id"]
	},
	{
		"name": "medium_vulnerability_sla_breach",
		"title": "{{ .cve_id }}: medium severity vulnerability exceeded remediation SLA",
		"statement": "{{ .cve_id }} affects {{ .package_name }} ({{ .ecosystem }}) in repository {{ .repository }} and has remained open beyond the medium vulnerability remediation SLA.",
		"likelihood_hint": "moderate",
		"impact_hint": "moderate",
		"violation_ids": ["medium_vulnerability_sla_breached"],
		"dedupe_label_keys": ["cve_id"]
	},
	{
		"name": "low_vulnerability_sla_breach",
		"title": "{{ .cve_id }}: low severity vulnerability exceeded remediation SLA",
		"statement": "{{ .cve_id }} affects {{ .package_name }} ({{ .ecosystem }}) in repository {{ .repository }} and has remained open beyond the low vulnerability remediation SLA.",
		"likelihood_hint": "low",
		"impact_hint": "moderate",
		"violation_ids": ["low_vulnerability_sla_breached"],
		"dedupe_label_keys": ["cve_id"]
	}
]

_advisory_id := input[0].security_advisory.cve_id if {
	input[0].security_advisory.cve_id != ""
} else := input[0].security_advisory.ghsa_id

default title := "Vulnerability remediation SLA is met"

title := sprintf("%s vulnerability remediation SLA is met", [_advisory_id]) if {
	_advisory_id != ""
}

description := "Open Dependabot alerts should be remediated within the SLA for their severity."
