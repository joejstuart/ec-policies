package compound_007

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have a reference with kind 'Task'.
# description: >-
#   Verify all tasks in the PipelineRun attestation have a reference with kind 'Task'.
# custom:
#   short_name: compound_007
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.ref.kind != "Task"
	result := sprintf("Task %s reference kind is %s, expected Task", [task.name, task.ref.kind])
}
