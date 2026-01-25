package metadata_008

import rego.v1

# METADATA
# title: Verify the build finished timestamp exists in the attestation metadata.
# description: >-
#   Verify the build finished timestamp exists in the attestation metadata.
# custom:
#   short_name: metadata_008
#
deny contains result if {
	some attestation in input.attestations
	not attestation.statement.predicate.metadata.buildFinishedOn
	result := "Attestation does not have buildFinishedOn timestamp"
}
