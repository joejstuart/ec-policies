package single_key_022

import rego.v1

# METADATA
# title: Verify the build task's IMAGE_DIGEST result starts with 'sha256:'.
# description: >-
#   Verify the build task's IMAGE_DIGEST result starts with 'sha256:'.
# custom:
#   short_name: single_key_022
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	some task_result in task.results
	task_result.name == "IMAGE_DIGEST"
	not startswith(task_result.value, "sha256:")
	result := sprintf("Build task IMAGE_DIGEST result does not start with sha256:: %s", [task_result.value])
}
