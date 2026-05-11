package compliance_framework.dependabot_granular_stale_dismissed_alert_test

import data.compliance_framework.dependabot_granular_stale_dismissed_alert

mock_alert := {
	"state": "dismissed",
	"dismissed_at": "2025-01-01T00:00:00Z",
	"security_advisory": {"cve_id": "CVE-2024-1234"},
	"security_vulnerability": {"severity": "medium"},
	"dependency": {"package": {"name": "lodash", "ecosystem": "npm"}},
}

test_old_dismissed_alert_produces_violation if {
	now := time.parse_rfc3339_ns("2025-05-01T00:00:00Z")
	violations := dependabot_granular_stale_dismissed_alert.violation with input as [mock_alert] with time.now_ns as now
	violations[{"id": "dismissal_not_reassessed"}]
}

test_recent_dismissed_alert_no_violation if {
	now := time.parse_rfc3339_ns("2025-03-01T00:00:00Z")
	violations := dependabot_granular_stale_dismissed_alert.violation with input as [mock_alert] with time.now_ns as now
	count(violations) == 0
}

test_non_dismissed_alert_no_violation if {
	now := time.parse_rfc3339_ns("2025-05-01T00:00:00Z")
	alert := object.union(mock_alert, {"dismissed_at": null})
	violations := dependabot_granular_stale_dismissed_alert.violation with input as [alert] with time.now_ns as now
	count(violations) == 0
}

test_risk_template_has_required_fields if {
	tpl := dependabot_granular_stale_dismissed_alert.risk_templates[0]
	tpl.name == "stale_vulnerability_dismissal"
	tpl.violation_ids == ["dismissal_not_reassessed"]
	tpl.dedupe_label_keys == ["cve_id"]
}

test_title_uses_cve_id_when_present if {
	t := dependabot_granular_stale_dismissed_alert.title with input as [mock_alert]
	t == "CVE-2024-1234 dismissed vulnerability is reassessed"
}
