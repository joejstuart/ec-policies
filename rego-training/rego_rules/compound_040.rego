package compound_040

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have results with values set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have results with values set.
# custom:
#   short_name: compound_040
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some task_result in task.results
	not task_result.value
	result := sprintf("Task %s has result %s without value", [task.name, task_result.name])
}
