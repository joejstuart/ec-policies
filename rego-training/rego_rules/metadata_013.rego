package metadata_013

import rego.v1

# METADATA
# title: Verify the build completeness indicates materials are complete.
# description: >-
#   Verify the build completeness indicates materials are complete.
# custom:
#   short_name: metadata_013
#
deny contains result if {
	some attestation in input.attestations
	completeness := attestation.statement.predicate.metadata.completeness
	completeness.materials != true
	result := "Build completeness indicates materials are not complete"
}
