package compound_098

import rego.v1

# METADATA
# title: Verify all tasks that have an 'output-image' parameter produced an IMAGE_URL result with matching value.
# description: >-
#   Verify all tasks that have an 'output-image' parameter produced an IMAGE_URL result with matching value.
# custom:
#   short_name: compound_098
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	output_image := task.invocation.parameters["output-image"]
	output_image
	image_url_result := {r.value | some r in task.results; r.name == "IMAGE_URL"}
	not output_image in image_url_result
	result := sprintf("Task %s output-image parameter does not match IMAGE_URL result", [task.name])
}
