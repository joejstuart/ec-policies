package single_key_017

import rego.v1

# METADATA
# title: Verify the build task has at least one step.
# description: >-
#   Verify the build task has at least one step.
# custom:
#   short_name: single_key_017
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	count(task.steps) == 0
	result := "Build task has no steps"
}
