package subject_003

import rego.v1

# METADATA
# title: Verify the attestation has at least one subject image.
# description: >-
#   Verify the attestation has at least one subject image.
# custom:
#   short_name: subject_003
#
deny contains result if {
	some attestation in input.attestations
	count(attestation.statement.subject) == 0
	result := "Attestation has no subject images"
}
