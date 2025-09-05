#
# METADATA
# title: Schedule related checks
# description: >-
#   Rules that verify the current date conform to a given schedule.
#
package schedule

import rego.v1

import data.lib
import data.lib.json as j



# METADATA
# title: Rule data provided
# description: >-
#   Confirm the expected rule data keys have been provided in the expected format. The keys are
#   `disallowed_weekdays` and `disallowed_dates`.
# custom:
#   short_name: rule_data_provided
#   failure_msg: '%s'
#   solution: If provided, ensure the rule data is in the expected format.
#   collections:
#   - redhat
#   - redhat_rpms
#   - policy_data
#
deny contains result if {
	# (For this one let's do it always)
	some e in _rule_data_errors
	result := lib.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

_rule_data_errors contains error if {
	key := "disallowed_weekdays"

	# JSON Schema doesn't allow case insensitive enum types. So here we define a list of all the
	# weekdays as "title-case", lower case, and upper case.
	titled_weekdays := ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
	weekdays := array.concat(
		array.concat(
			titled_weekdays,
			[lower(d) | some d in titled_weekdays],
		),
		[upper(d) | some d in titled_weekdays],
	)

	some e in j.validate_schema(
		lib.rule_data(key),
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"enum": weekdays},
			"uniqueItems": true,
		},
	)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [key, e.message]),
		"severity": e.severity,
	}
}

_rule_data_errors contains error if {
	# IMPORTANT: Although the JSON schema spec does allow specifying a regular expression to match
	# values, via the "pattern" attribute, rego's JSON schema validator does not:
	# https://github.com/open-policy-agent/opa/issues/6089
	key := "disallowed_dates"

	some e in j.validate_schema(
		lib.rule_data(key),
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			"uniqueItems": true,
		},
	)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [key, e.message]),
		"severity": e.severity,
	}
}

_rule_data_errors contains error if {
	key := "disallowed_dates"
	some index, date in lib.rule_data(key)
	not time.parse_ns("2006-01-02", date)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %d: Invalid date %q", [key, index, date]),
		"severity": "failure",
	}
}
