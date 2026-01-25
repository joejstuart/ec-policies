package single_key_005

import rego.v1

# METADATA
# title: Verify the build task has a bundle reference.
# description: >-
#   Verify the build task has a bundle reference.
# custom:
#   short_name: single_key_005
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	not task.ref.bundle
	result := "Build task does not have a bundle reference"
}
