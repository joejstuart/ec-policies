package slsa_v1_221

import rego.v1

# METADATA
# title: Verify the SLSA v1.0 attestation internalParameters has labels.
# description: >-
#   Verify the SLSA v1.0 attestation internalParameters has labels.
# custom:
#   short_name: slsa_v1_221
#
deny contains result if {
	some attestation in input.attestations
	attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
	not attestation.statement.predicate.buildDefinition.internalParameters.labels
	result := "SLSA v1.0 attestation internalParameters does not have labels"
}
