package single_key_029

import rego.v1

# METADATA
# title: Verify the build task has a configSource with a uri.
# description: >-
#   Verify the build task has a configSource with a uri.
# custom:
#   short_name: single_key_029
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	not task.invocation.configSource.uri
	result := "Build task does not have configSource uri"
}
