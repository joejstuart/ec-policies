package slsa_v1_220

import rego.v1

# METADATA
# title: Verify the SLSA v1.0 attestation externalParameters has runSpec with pipelineSpec.
# description: >-
#   Verify the SLSA v1.0 attestation externalParameters has runSpec with pipelineSpec.
# custom:
#   short_name: slsa_v1_220
#
deny contains result if {
	some attestation in input.attestations
	attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
	not attestation.statement.predicate.buildDefinition.externalParameters.runSpec.pipelineSpec
	result := "SLSA v1.0 attestation externalParameters.runSpec does not have pipelineSpec"
}
