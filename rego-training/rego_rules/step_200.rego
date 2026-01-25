package step_200

import rego.v1

# METADATA
# title: Verify all steps in all tasks have environment container that is not empty when set.
# description: >-
#   Verify all steps in all tasks have environment container that is not empty when set.
# custom:
#   short_name: step_200
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some step in task.steps
	container := step.environment.container
	container
	container == ""
	result := sprintf("Task %s has step with empty container name", [task.name])
}
