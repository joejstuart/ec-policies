package step_034

import rego.v1

# METADATA
# title: Verify all steps in all tasks have environment image with digest.
# description: >-
#   Verify all steps in all tasks have environment image with digest.
# custom:
#   short_name: step_034
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some step in task.steps
	image := step.environment.image
	image
	not contains(image, "@sha256:")
	result := sprintf("Task %s has step with image without digest: %s", [task.name, image])
}
