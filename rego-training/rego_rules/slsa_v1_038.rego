package slsa_v1_038

import rego.v1

# METADATA
# title: Verify the SLSA v1.0 attestation has runDetails with metadata.
# description: >-
#   Verify the SLSA v1.0 attestation has runDetails with metadata.
# custom:
#   short_name: slsa_v1_038
#
deny contains result if {
	some attestation in input.attestations
	attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
	not attestation.statement.predicate.runDetails.metadata
	result := "SLSA v1.0 attestation does not have runDetails metadata"
}
