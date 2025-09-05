#
# METADATA
# title: Schedule Release
# description: >-
#   Release-specific schedule related checks. These rules are enforced only for
#   "release" or "production" pipelines, as determined by the pipeline_intention
#   rule data.
#
package schedule_release

import rego.v1

import data.lib

# METADATA
# title: Weekday Restriction
# description: >-
#   Check if the current weekday is allowed based on the rule data value from the key
#   `disallowed_weekdays`. By default, the list is empty in which case *any* weekday is
#   allowed. This check is enforced only for a "release" or "production"
#   pipeline, as determined by the value of the `pipeline_intention` rule data.
# custom:
#   short_name: weekday_restriction
#   pipeline_intention:
#   - release
#   - production
#   failure_msg: '%s is a disallowed weekday: %s'
#   solution: Try again on a different weekday.
#   collections:
#   - redhat
#   - redhat_rpms
#
deny contains result if {
	lib.pipeline_intention_match(rego.metadata.chain())
	today := lower(time.weekday(lib.time.effective_current_time_ns))
	disallowed := {lower(w) | some w in lib.rule_data("disallowed_weekdays")}
	count(disallowed) > 0
	today in disallowed
	result := lib.result_helper(rego.metadata.chain(), [today, concat(", ", disallowed)])
}

# METADATA
# title: Date Restriction
# description: >-
#   Check if the current date is not allowed based on the rule data value
#   from the key `disallowed_dates`. By default, the list is empty in which
#   case *any* day is allowed. This check is enforced only for a "release" or
#   "production" pipeline, as determined by the value of the
#   `pipeline_intention` rule data.
# custom:
#   short_name: date_restriction
#   pipeline_intention:
#   - release
#   - production
#   failure_msg: '%s is a disallowed date: %s'
#   solution: Try again on a different day.
#   collections:
#   - redhat
#   - redhat_rpms
#
deny contains result if {
	lib.pipeline_intention_match(rego.metadata.chain())
	today := time.format([lib.time.effective_current_time_ns, "UTC", "2006-01-02"])
	disallowed := lib.rule_data("disallowed_dates")
	today in disallowed
	result := lib.result_helper(rego.metadata.chain(), [today, concat(", ", disallowed)])
}
