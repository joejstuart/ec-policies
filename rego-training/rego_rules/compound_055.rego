package compound_055

import rego.v1

# METADATA
# title: Verify all tasks with bundle references have both bundle and digest.
# description: >-
#   Verify all tasks with bundle references have both bundle and digest.
# custom:
#   short_name: compound_055
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	bundle := task.ref.bundle
	bundle
	not contains(bundle, "@sha256:")
	not contains(bundle, "@sha1:")
	result := sprintf("Task %s bundle %s does not have digest", [task.name, bundle])
}
