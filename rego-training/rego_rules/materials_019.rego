package materials_019

import rego.v1

# METADATA
# title: Verify all materials in the attestation have a digest.
# description: >-
#   Verify all materials in the attestation have a digest.
# custom:
#   short_name: materials_019
#
deny contains result if {
	some attestation in input.attestations
	some material in attestation.statement.predicate.materials
	not material.digest
	result := sprintf("Material %s does not have a digest", [material.uri])
}
