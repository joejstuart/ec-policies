package compound_039

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have results with names set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have results with names set.
# custom:
#   short_name: compound_039
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some task_result in task.results
	not task_result.name
	result := sprintf("Task %s has result without name", [task.name])
}
