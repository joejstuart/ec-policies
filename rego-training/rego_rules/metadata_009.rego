package metadata_009

import rego.v1

# METADATA
# title: Verify the build started timestamp exists in the attestation metadata.
# description: >-
#   Verify the build started timestamp exists in the attestation metadata.
# custom:
#   short_name: metadata_009
#
deny contains result if {
	some attestation in input.attestations
	not attestation.statement.predicate.metadata.buildStartedOn
	result := "Attestation does not have buildStartedOn timestamp"
}
