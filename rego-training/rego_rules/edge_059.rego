package edge_059

import rego.v1

# METADATA
# title: Verify the attestation has at least one task.
# description: >-
#   Verify the attestation has at least one task.
# custom:
#   short_name: edge_059
#
deny contains result if {
	some attestation in input.attestations
	count(attestation.statement.predicate.buildConfig.tasks) == 0
	result := "Attestation has no tasks"
}
