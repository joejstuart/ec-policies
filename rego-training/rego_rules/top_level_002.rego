package top_level_002

import rego.v1

# METADATA
# title: Verify the attestation has predicateType 'https://slsa.dev/provenance/v0.2'.
# description: >-
#   Verify the attestation has predicateType 'https://slsa.dev/provenance/v0.2'.
# custom:
#   short_name: top_level_002
#
deny contains result if {
	some attestation in input.attestations
	attestation.statement.predicateType != "https://slsa.dev/provenance/v0.2"
	result := sprintf("Attestation has incorrect predicateType: %s", [attestation.statement.predicateType])
}
