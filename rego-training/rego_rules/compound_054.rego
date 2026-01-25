package compound_054

import rego.v1

# METADATA
# title: Verify all tasks that succeeded have at least one result.
# description: >-
#   Verify all tasks that succeeded have at least one result.
# custom:
#   short_name: compound_054
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.status == "Succeeded"
	count(task.results) == 0
	result := sprintf("Task %s succeeded but has no results", [task.name])
}
