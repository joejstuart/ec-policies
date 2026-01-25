package step_199

import rego.v1

# METADATA
# title: Verify all steps in all tasks have environment image that is not empty.
# description: >-
#   Verify all steps in all tasks have environment image that is not empty.
# custom:
#   short_name: step_199
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some step in task.steps
	image := step.environment.image
	image == ""
	result := sprintf("Task %s has step with empty image", [task.name])
}
