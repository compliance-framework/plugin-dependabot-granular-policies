package compliance_framework.dependabot_granular_open_alert_test

import data.compliance_framework.dependabot_granular_open_alert
import future.keywords.in

# -- helpers ------------------------------------------------------------------

mock_open_alert := {
	"state": "open",
	"security_advisory": {
		"cve_id": "CVE-2024-1234",
		"ghsa_id": "GHSA-xxxx-yyyy-zzzz",
		"cvss": {"score": 9.8},
	},
	"security_vulnerability": {"severity": "critical"},
	"dependency": {
		"package": {
			"name": "lodash",
			"ecosystem": "npm",
		},
	},
}

mock_fixed_alert := object.union(mock_open_alert, {"state": "fixed"})

mock_dismissed_alert := object.union(mock_open_alert, {"state": "dismissed"})

# -- violation tests ----------------------------------------------------------

test_open_alert_produces_violation if {
	violations := dependabot_granular_open_alert.violation with input as [mock_open_alert]
	violations[{"id": "open_cve_alert"}]
}

test_fixed_alert_no_violation if {
	violations := dependabot_granular_open_alert.violation with input as [mock_fixed_alert]
	count(violations) == 0
}

test_dismissed_alert_no_violation if {
	violations := dependabot_granular_open_alert.violation with input as [mock_dismissed_alert]
	count(violations) == 0
}

# -- risk_templates shape tests -----------------------------------------------

test_risk_templates_present if {
	count(dependabot_granular_open_alert.risk_templates) > 0
}

test_risk_template_has_required_fields if {
	tpl := dependabot_granular_open_alert.risk_templates[0]
	tpl.name == "open_cve_vulnerability"
	tpl.violation_ids == ["open_cve_alert"]
	tpl.dedupe_label_keys == ["cve_id"]
}

mock_ghsa_only_alert := object.union(
	object.remove(mock_open_alert, ["security_advisory"]),
	{"security_advisory": {"ghsa_id": "GHSA-xxxx-yyyy-zzzz"}},
)

test_title_uses_cve_id_when_present if {
	t := dependabot_granular_open_alert.title with input as [mock_open_alert]
	t == "CVE-2024-1234 vulnerability is remediated"
}

test_title_falls_back_to_ghsa_id_when_no_cve if {
	t := dependabot_granular_open_alert.title with input as [mock_ghsa_only_alert]
	t == "GHSA-xxxx-yyyy-zzzz vulnerability is remediated"
}

test_title_falls_back_to_default_when_no_advisory_id if {
	t := dependabot_granular_open_alert.title with input as [{}]
	t == "CVE vulnerability is remediated"
}
