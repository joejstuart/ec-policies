package step_088

import rego.v1

# METADATA
# title: Verify all steps in all tasks that have entryPoint have a non-empty entryPoint.
# description: >-
#   Verify all steps in all tasks that have entryPoint have a non-empty entryPoint.
# custom:
#   short_name: step_088
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some step in task.steps
	step.entryPoint == ""
	result := sprintf("Task %s has step with empty entryPoint", [task.name])
}
