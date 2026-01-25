package materials_201

import rego.v1

# METADATA
# title: Verify all materials have URIs that are not empty strings.
# description: >-
#   Verify all materials have URIs that are not empty strings.
# custom:
#   short_name: materials_201
#
deny contains result if {
	some attestation in input.attestations
	some material in attestation.statement.predicate.materials
	material.uri == ""
	result := "Material has empty URI"
}
