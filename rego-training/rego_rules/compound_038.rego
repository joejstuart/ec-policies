package compound_038

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have results with non-empty values.
# description: >-
#   Verify all tasks in the PipelineRun attestation have results with non-empty values.
# custom:
#   short_name: compound_038
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some task_result in task.results
	task_result.value == ""
	result := sprintf("Task %s has result %s with empty value", [task.name, task_result.name])
}
