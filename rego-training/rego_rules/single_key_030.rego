package single_key_030

import rego.v1

# METADATA
# title: Verify the build task has a configSource with a digest.
# description: >-
#   Verify the build task has a configSource with a digest.
# custom:
#   short_name: single_key_030
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	not task.invocation.configSource.digest
	result := "Build task does not have configSource digest"
}
