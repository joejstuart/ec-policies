package slsa_v1_222

import rego.v1

# METADATA
# title: Verify the SLSA v1.0 attestation internalParameters has annotations.
# description: >-
#   Verify the SLSA v1.0 attestation internalParameters has annotations.
# custom:
#   short_name: slsa_v1_222
#
deny contains result if {
	some attestation in input.attestations
	attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
	not attestation.statement.predicate.buildDefinition.internalParameters.annotations
	result := "SLSA v1.0 attestation internalParameters does not have annotations"
}
