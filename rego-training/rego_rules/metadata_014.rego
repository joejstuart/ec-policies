package metadata_014

import rego.v1

# METADATA
# title: Verify the build completeness indicates parameters are complete.
# description: >-
#   Verify the build completeness indicates parameters are complete.
# custom:
#   short_name: metadata_014
#
deny contains result if {
	some attestation in input.attestations
	completeness := attestation.statement.predicate.metadata.completeness
	completeness.parameters != true
	result := "Build completeness indicates parameters are not complete"
}
