package schedule_release_test

import rego.v1

import data.lib
import data.schedule_release

test_weekday_restriction if {
	_rule_data := weekday_rule_data(["friday", "saturday", "sunday"])

	lib.assert_empty(schedule_release.deny) with data.rule_data as _rule_data
		with data.config.policy.when_ns as monday

	lib.assert_empty(schedule_release.deny) with data.rule_data as _rule_data
		with data.config.policy.when_ns as tuesday

	lib.assert_empty(schedule_release.deny) with data.rule_data as _rule_data
		with data.config.policy.when_ns as wednesday

	lib.assert_empty(schedule_release.deny) with data.rule_data as _rule_data
		with data.config.policy.when_ns as thursday

	friday_violation := {{
		"code": "schedule_release.weekday_restriction",
		"msg": "friday is a disallowed weekday: friday, saturday, sunday",
	}}
	lib.assert_equal_results(schedule_release.deny, friday_violation) with data.rule_data as _rule_data
		with data.config.policy.when_ns as friday

	saturday_violation := {{
		"code": "schedule_release.weekday_restriction",
		"msg": "saturday is a disallowed weekday: friday, saturday, sunday",
	}}
	lib.assert_equal_results(schedule_release.deny, saturday_violation) with data.rule_data as _rule_data
		with data.config.policy.when_ns as saturday

	sunday_violation := {{
		"code": "schedule_release.weekday_restriction",
		"msg": "sunday is a disallowed weekday: friday, saturday, sunday",
	}}
	lib.assert_equal_results(schedule_release.deny, sunday_violation) with data.rule_data as _rule_data
		with data.config.policy.when_ns as sunday
}

test_weekday_restriction_case_insensitive if {
	violation := {{
		"code": "schedule_release.weekday_restriction",
		"msg": "friday is a disallowed weekday: friday",
	}}

	lib.assert_equal_results(schedule_release.deny, violation) with data.rule_data as weekday_rule_data(["FRIDAY"])
		with data.config.policy.when_ns as friday
	lib.assert_empty(schedule_release.deny) with data.rule_data as weekday_rule_data(["FRIDAY"])
		with data.config.policy.when_ns as monday

	lib.assert_equal_results(schedule_release.deny, violation) with data.rule_data as weekday_rule_data(["friday"])
		with data.config.policy.when_ns as friday
	lib.assert_empty(schedule_release.deny) with data.rule_data as weekday_rule_data(["friday"])
		with data.config.policy.when_ns as monday
}

test_date_restriction if {
	violation := {{
		"code": "schedule_release.date_restriction",
		"msg": "2023-01-01 is a disallowed date: 2023-01-01",
	}}
	lib.assert_equal_results(schedule_release.deny, violation) with data.rule_data as date_rule_data(["2023-01-01"])
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-01-01T00:00:00Z")

	lib.assert_empty(schedule_release.deny) with data.rule_data as date_rule_data(["2023-01-01"])
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-01-02T00:00:00Z")
	lib.assert_empty(schedule_release.deny) with data.rule_data as date_rule_data(["2023-01-01"])
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-02-01T00:00:00Z")
	lib.assert_empty(schedule_release.deny) with data.rule_data as date_rule_data(["2023-01-01"])
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2024-01-01T00:00:00Z")
	lib.assert_empty(schedule_release.deny) with data.rule_data as date_rule_data(["2023-01-01"])
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2024-02-03T00:00:00Z")
}

test_pipeline_intention if {
	# With pipeline intention set to "release" we get a violation
	release_weekday_data := weekday_rule_data(["monday"])
	monday_violation := {{
		"code": "schedule_release.weekday_restriction",
		"msg": "monday is a disallowed weekday: monday",
	}}
	lib.assert_equal_results(schedule_release.deny, monday_violation) with data.rule_data as release_weekday_data
		with data.config.policy.when_ns as monday

	release_date_data := date_rule_data(["2024-05-12"])
	rfc_date := time.parse_rfc3339_ns("2024-05-12T00:00:00Z")
	violation := {{
		"code": "schedule_release.date_restriction",
		"msg": "2024-05-12 is a disallowed date: 2024-05-12",
	}}
	lib.assert_equal_results(schedule_release.deny, violation) with data.rule_data as release_date_data
		with data.config.policy.when_ns as rfc_date

	# Without pipeline intention set to "release" we do not get a violation
	build_weekday_data := object.union(release_weekday_data, {"pipeline_intention": null})
	lib.assert_empty(schedule_release.deny) with data.rule_data as build_weekday_data
		with data.config.policy.when_ns as monday

	spam_weekday_data := object.union(release_weekday_data, {"pipeline_intention": "spam"})
	lib.assert_empty(schedule_release.deny) with data.rule_data as spam_weekday_data
		with data.config.policy.when_ns as monday

	build_date_data := object.union(release_date_data, {"pipeline_intention": null})
	lib.assert_empty(schedule_release.deny) with data.rule_data as build_date_data
		with data.config.policy.when_ns as rfc_date

	spam_date_data := object.union(release_date_data, {"pipeline_intention": "spam"})
	lib.assert_empty(schedule_release.deny) with data.rule_data as spam_date_data
		with data.config.policy.when_ns as rfc_date
}

sunday := _rfc_time_helper("2023-01-01")

monday := _rfc_time_helper("2023-01-02")

tuesday := _rfc_time_helper("2023-01-03")

wednesday := _rfc_time_helper("2023-01-04")

thursday := _rfc_time_helper("2023-01-05")

friday := _rfc_time_helper("2023-01-06")

saturday := _rfc_time_helper("2023-01-07")

_rfc_time_helper(date_string) := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [date_string]))

weekday_rule_data(disallowed_weekdays) := _rule_data_helper("disallowed_weekdays", disallowed_weekdays, "release")

date_rule_data(disallowed_dates) := _rule_data_helper("disallowed_dates", disallowed_dates, "release")

_rule_data_helper(disallowed_key, disallowed_values, pipeline_intention) := {
	"pipeline_intention": pipeline_intention,
	disallowed_key: disallowed_values,
}
