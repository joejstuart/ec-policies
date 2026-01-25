package single_key_021

import rego.v1

# METADATA
# title: Verify the build task's IMAGE_URL result contains 'quay.io'.
# description: >-
#   Verify the build task's IMAGE_URL result contains 'quay.io'.
# custom:
#   short_name: single_key_021
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	some task_result in task.results
	task_result.name == "IMAGE_URL"
	not contains(task_result.value, "quay.io")
	result := sprintf("Build task IMAGE_URL result does not contain quay.io: %s", [task_result.value])
}
