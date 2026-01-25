package materials_018

import rego.v1

# METADATA
# title: Verify all materials in the attestation have a URI.
# description: >-
#   Verify all materials in the attestation have a URI.
# custom:
#   short_name: materials_018
#
deny contains result if {
	some attestation in input.attestations
	some material in attestation.statement.predicate.materials
	not material.uri
	result := "Material does not have a URI"
}
