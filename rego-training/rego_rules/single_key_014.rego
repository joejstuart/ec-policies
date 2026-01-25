package single_key_014

import rego.v1

# METADATA
# title: Verify the build task started timestamp exists.
# description: >-
#   Verify the build task started timestamp exists.
# custom:
#   short_name: single_key_014
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	not task.startedOn
	result := "Build task does not have startedOn timestamp"
}
