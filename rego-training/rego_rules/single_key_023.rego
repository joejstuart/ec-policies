package single_key_023

import rego.v1

# METADATA
# title: Verify the build task bundle reference is from quay.io.
# description: >-
#   Verify the build task bundle reference is from quay.io.
# custom:
#   short_name: single_key_023
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	bundle := task.ref.bundle
	bundle
	not contains(bundle, "quay.io")
	result := sprintf("Build task bundle %s is not from quay.io", [bundle])
}
