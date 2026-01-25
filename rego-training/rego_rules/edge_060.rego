package edge_060

import rego.v1

# METADATA
# title: Verify the attestation has at least one subject.
# description: >-
#   Verify the attestation has at least one subject.
# custom:
#   short_name: edge_060
#
deny contains result if {
	some attestation in input.attestations
	count(attestation.statement.subject) == 0
	result := "Attestation has no subject images"
}
