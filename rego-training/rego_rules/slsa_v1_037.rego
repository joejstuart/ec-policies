package slsa_v1_037

import rego.v1

# METADATA
# title: Verify the SLSA v1.0 attestation has internalParameters.
# description: >-
#   Verify the SLSA v1.0 attestation has internalParameters.
# custom:
#   short_name: slsa_v1_037
#
deny contains result if {
	some attestation in input.attestations
	attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
	not attestation.statement.predicate.buildDefinition.internalParameters
	result := "SLSA v1.0 attestation does not have internalParameters"
}
