package edge_061

import rego.v1

# METADATA
# title: Verify the attestation has at least one material.
# description: >-
#   Verify the attestation has at least one material.
# custom:
#   short_name: edge_061
#
deny contains result if {
	some attestation in input.attestations
	count(attestation.statement.predicate.materials) == 0
	result := "Attestation has no materials"
}
