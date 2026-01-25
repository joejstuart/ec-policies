package materials_016

import rego.v1

# METADATA
# title: Verify the attestation has a materials section.
# description: >-
#   Verify the attestation has a materials section.
# custom:
#   short_name: materials_016
#
deny contains result if {
	some attestation in input.attestations
	not attestation.statement.predicate.materials
	result := "Attestation does not have materials section"
}
