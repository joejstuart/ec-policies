package single_key_009

import rego.v1

# METADATA
# title: Verify the build task's IMAGE_URL result has a non-empty value.
# description: >-
#   Verify the build task's IMAGE_URL result has a non-empty value.
# custom:
#   short_name: single_key_009
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	some task_result in task.results
	task_result.name == "IMAGE_URL"
	task_result.value == ""
	result := "Build task IMAGE_URL result is empty"
}
