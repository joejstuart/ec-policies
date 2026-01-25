package single_key_031

import rego.v1

# METADATA
# title: Verify the build task configSource digest has sha256.
# description: >-
#   Verify the build task configSource digest has sha256.
# custom:
#   short_name: single_key_031
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	digest := task.invocation.configSource.digest
	digest
	not digest.sha256
	result := "Build task configSource digest does not have sha256"
}
