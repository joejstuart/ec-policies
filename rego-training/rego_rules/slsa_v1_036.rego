package slsa_v1_036

import rego.v1

# METADATA
# title: Verify the SLSA v1.0 attestation has externalParameters.
# description: >-
#   Verify the SLSA v1.0 attestation has externalParameters.
# custom:
#   short_name: slsa_v1_036
#
deny contains result if {
	some attestation in input.attestations
	attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
	not attestation.statement.predicate.buildDefinition.externalParameters
	result := "SLSA v1.0 attestation does not have externalParameters"
}
