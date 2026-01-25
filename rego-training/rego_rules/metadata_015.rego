package metadata_015

import rego.v1

# METADATA
# title: Verify the build is marked as reproducible.
# description: >-
#   Verify the build is marked as reproducible.
# custom:
#   short_name: metadata_015
#
deny contains result if {
	some attestation in input.attestations
	attestation.statement.predicate.metadata.reproducible != true
	result := "Build is not marked as reproducible"
}
