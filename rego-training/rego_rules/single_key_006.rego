package single_key_006

import rego.v1

# METADATA
# title: Verify the build task bundle reference contains a digest (has @sha256:).
# description: >-
#   Verify the build task bundle reference contains a digest (has @sha256:).
# custom:
#   short_name: single_key_006
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	bundle := task.ref.bundle
	bundle
	not contains(bundle, "@sha256:")
	result := sprintf("Build task bundle %s does not contain digest", [bundle])
}
