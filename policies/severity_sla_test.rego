package compliance_framework.dependabot_granular_severity_sla_test

import data.compliance_framework.dependabot_granular_severity_sla as severity_sla

base_alert := {
	"state": "open",
	"created_at": "2025-01-01T00:00:00Z",
	"security_advisory": {"cve_id": "CVE-2024-1234"},
	"security_vulnerability": {"severity": "critical"},
	"dependency": {"package": {"name": "lodash", "ecosystem": "npm"}},
}

test_critical_sla_breach_violation if {
	now := time.parse_rfc3339_ns("2025-01-10T00:00:00Z")
	violations := severity_sla.violation with input as [base_alert] with time.now_ns as now
	violations[{"id": "critical_vulnerability_sla_breached"}]
}

test_critical_within_sla_no_violation if {
	now := time.parse_rfc3339_ns("2025-01-03T00:00:00Z")
	violations := severity_sla.violation with input as [base_alert] with time.now_ns as now
	count(violations) == 0
}

test_high_sla_breach_violation if {
	now := time.parse_rfc3339_ns("2025-01-20T00:00:00Z")
	alert := object.union(base_alert, {"security_vulnerability": {"severity": "high"}})
	violations := severity_sla.violation with input as [alert] with time.now_ns as now
	violations[{"id": "high_vulnerability_sla_breached"}]
}

test_medium_sla_breach_violation if {
	now := time.parse_rfc3339_ns("2025-02-01T00:00:00Z")
	alert := object.union(base_alert, {"security_vulnerability": {"severity": "medium"}})
	violations := severity_sla.violation with input as [alert] with time.now_ns as now
	violations[{"id": "medium_vulnerability_sla_breached"}]
}

test_low_sla_breach_violation if {
	now := time.parse_rfc3339_ns("2025-04-01T00:00:00Z")
	alert := object.union(base_alert, {"security_vulnerability": {"severity": "low"}})
	violations := severity_sla.violation with input as [alert] with time.now_ns as now
	violations[{"id": "low_vulnerability_sla_breached"}]
}

test_non_open_alert_no_violation if {
	now := time.parse_rfc3339_ns("2025-04-01T00:00:00Z")
	alert := object.union(base_alert, {"state": "fixed"})
	violations := severity_sla.violation with input as [alert] with time.now_ns as now
	count(violations) == 0
}

test_risk_templates_present if {
	count(severity_sla.risk_templates) == 4
}

test_title_uses_cve_id_when_present if {
	t := severity_sla.title with input as [base_alert]
	t == "CVE-2024-1234 vulnerability remediation SLA is met"
}
