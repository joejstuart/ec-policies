package single_key_010

import rego.v1

# METADATA
# title: Verify the build task's IMAGE_DIGEST result has a non-empty value.
# description: >-
#   Verify the build task's IMAGE_DIGEST result has a non-empty value.
# custom:
#   short_name: single_key_010
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	some task_result in task.results
	task_result.name == "IMAGE_DIGEST"
	task_result.value == ""
	result := "Build task IMAGE_DIGEST result is empty"
}
