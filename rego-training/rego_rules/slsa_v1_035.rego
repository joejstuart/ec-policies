package slsa_v1_035

import rego.v1

# METADATA
# title: Verify the attestation has buildDefinition with buildType 'https://tekton.dev/chains/v2/slsa-tekton'.
# description: >-
#   Verify the attestation has buildDefinition with buildType 'https://tekton.dev/chains/v2/slsa-tekton'.
# custom:
#   short_name: slsa_v1_035
#
deny contains result if {
	some attestation in input.attestations
	attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
	build_type := attestation.statement.predicate.buildDefinition.buildType
	build_type != "https://tekton.dev/chains/v2/slsa-tekton"
	result := sprintf("Attestation has incorrect buildType: %s", [build_type])
}
