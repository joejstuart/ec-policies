package single_key_018

import rego.v1

# METADATA
# title: Verify the build task has at least one result.
# description: >-
#   Verify the build task has at least one result.
# custom:
#   short_name: single_key_018
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	count(task.results) == 0
	result := "Build task has no results"
}
