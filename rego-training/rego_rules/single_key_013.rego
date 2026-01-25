package single_key_013

import rego.v1

# METADATA
# title: Verify the build task finished timestamp exists.
# description: >-
#   Verify the build task finished timestamp exists.
# custom:
#   short_name: single_key_013
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	not task.finishedOn
	result := "Build task does not have finishedOn timestamp"
}
