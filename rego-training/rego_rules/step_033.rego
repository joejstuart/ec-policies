package step_033

import rego.v1

# METADATA
# title: Verify all steps in all tasks have environment image with oci:// prefix.
# description: >-
#   Verify all steps in all tasks have environment image with oci:// prefix.
# custom:
#   short_name: step_033
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some step in task.steps
	image := step.environment.image
	image
	not startswith(image, "oci://")
	result := sprintf("Task %s has step with image not using oci:// prefix: %s", [task.name, image])
}
