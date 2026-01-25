package result_212

import rego.v1

# METADATA
# title: Verify all tasks that have results have at least one result with a name.
# description: >-
#   Verify all tasks that have results have at least one result with a name.
# custom:
#   short_name: result_212
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some task_result in task.results
	not task_result.name
	result := sprintf("Task %s has result without name", [task.name])
}
