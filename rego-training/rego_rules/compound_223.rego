package compound_223

import rego.v1

# METADATA
# title: Verify all tasks have both started and finished timestamps when they have a status.
# description: >-
#   Verify all tasks have both started and finished timestamps when they have a status.
# custom:
#   short_name: compound_223
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
