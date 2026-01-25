package edge_063

import rego.v1

# METADATA
# title: Verify all materials have URIs that are not empty.
# description: >-
#   Verify all materials have URIs that are not empty.
# custom:
#   short_name: edge_063
#
deny contains result if {
	some attestation in input.attestations
	some material in attestation.statement.predicate.materials
	material.uri == ""
	result := "Material has empty URI"
}
