package task_026

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have reference params.
# description: >-
#   Verify all tasks in the PipelineRun attestation have reference params.
# custom:
#   short_name: task_026
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.ref.params
	result := sprintf("Task %s reference does not have params", [task.name])
}
