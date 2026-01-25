package slsa_v1_039

import rego.v1

# METADATA
# title: Verify the SLSA v1.0 attestation externalParameters has runSpec.
# description: >-
#   Verify the SLSA v1.0 attestation externalParameters has runSpec.
# custom:
#   short_name: slsa_v1_039
#
deny contains result if {
	some attestation in input.attestations
	attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
	not attestation.statement.predicate.buildDefinition.externalParameters.runSpec
	result := "SLSA v1.0 attestation externalParameters does not have runSpec"
}
