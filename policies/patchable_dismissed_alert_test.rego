package compliance_framework.dependabot_granular_patchable_dismissed_alert_test

import data.compliance_framework.dependabot_granular_patchable_dismissed_alert

mock_alert := {
	"state": "dismissed",
	"dismissed_at": "2025-09-11T16:24:18Z",
	"security_advisory": {
		"cve_id": "CVE-2024-1234",
		"ghsa_id": "GHSA-xxxx-yyyy-zzzz",
	},
	"security_vulnerability": {
		"severity": "high",
		"first_patched_version": {"identifier": "2.4.0"},
	},
	"dependency": {"package": {"name": "lodash", "ecosystem": "npm"}},
}

test_patchable_dismissed_alert_produces_violation if {
	violations := dependabot_granular_patchable_dismissed_alert.violation with input as [mock_alert]
	violations[{"id": "patchable_vulnerability_dismissed"}]
}

test_non_dismissed_patchable_alert_no_violation if {
	alert := object.union(mock_alert, {"dismissed_at": null})
	violations := dependabot_granular_patchable_dismissed_alert.violation with input as [alert]
	count(violations) == 0
}

test_dismissed_alert_without_patch_no_violation if {
	alert := object.union(mock_alert, {"security_vulnerability": {"severity": "high", "first_patched_version": null}})
	violations := dependabot_granular_patchable_dismissed_alert.violation with input as [alert]
	count(violations) == 0
}

test_risk_template_has_required_fields if {
	tpl := dependabot_granular_patchable_dismissed_alert.risk_templates[0]
	tpl.name == "patchable_vulnerability_dismissed"
	tpl.violation_ids == ["patchable_vulnerability_dismissed"]
	tpl.dedupe_label_keys == ["cve_id"]
}

test_title_uses_cve_id_when_present if {
	t := dependabot_granular_patchable_dismissed_alert.title with input as [mock_alert]
	t == "CVE-2024-1234 patchable dismissed vulnerability is remediated"
}
