package compound_019

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have at least one step.
# description: >-
#   Verify all tasks in the PipelineRun attestation have at least one step.
# custom:
#   short_name: compound_019
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	count(task.steps) == 0
	result := sprintf("Task %s has no steps", [task.name])
}
