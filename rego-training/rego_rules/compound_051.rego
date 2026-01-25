package compound_051

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have status values that are either 'Succeeded' or 'Failed'.
# description: >-
#   Verify all tasks in the PipelineRun attestation have status values that are either 'Succeeded' or 'Failed'.
# custom:
#   short_name: compound_051
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.status
	not task.status in {"Succeeded", "Failed"}
	result := sprintf("Task %s has invalid status: %s", [task.name, task.status])
}
