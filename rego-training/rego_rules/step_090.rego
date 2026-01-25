package step_090

import rego.v1

# METADATA
# title: Verify all steps in all tasks have environment image in valid format.
# description: >-
#   Verify all steps in all tasks have environment image in valid format.
# custom:
#   short_name: step_090
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some step in task.steps
	image := step.environment.image
	image
	not startswith(image, "oci://")
	not startswith(image, "docker://")
	result := sprintf("Task %s has step with invalid image format: %s", [task.name, image])
}
