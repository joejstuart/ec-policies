package metadata_012

import rego.v1

# METADATA
# title: Verify the build completeness indicates environment is complete.
# description: >-
#   Verify the build completeness indicates environment is complete.
# custom:
#   short_name: metadata_012
#
deny contains result if {
	some attestation in input.attestations
	completeness := attestation.statement.predicate.metadata.completeness
	completeness.environment != true
	result := "Build completeness indicates environment is not complete"
}
