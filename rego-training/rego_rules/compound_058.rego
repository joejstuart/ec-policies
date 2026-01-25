package compound_058

import rego.v1

# METADATA
# title: Verify all tasks that have a status also have both started and finished timestamps.
# description: >-
#   Verify all tasks that have a status also have both started and finished timestamps.
# custom:
#   short_name: compound_058
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.status
	not task.startedOn
	result := sprintf("Task %s has status but missing startedOn timestamp", [task.name])
}

deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.status
	not task.finishedOn
	result := sprintf("Task %s has status but missing finishedOn timestamp", [task.name])
}
