package metadata_011

import rego.v1

# METADATA
# title: Verify the build metadata has a completeness field.
# description: >-
#   Verify the build metadata has a completeness field.
# custom:
#   short_name: metadata_011
#
deny contains result if {
	some attestation in input.attestations
	not attestation.statement.predicate.metadata.completeness
	result := "Attestation does not have completeness metadata"
}
