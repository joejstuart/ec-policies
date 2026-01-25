package top_level_001

import rego.v1

# METADATA
# title: Verify the attestation statement has the correct _type field.
# description: >-
#   Verify the attestation statement has the correct _type field.
# custom:
#   short_name: top_level_001
#
deny contains result if {
	some attestation in input.attestations
	attestation.statement._type != "https://in-toto.io/Statement/v0.1"
	result := sprintf("Attestation has incorrect _type: %s", [attestation.statement._type])
}
