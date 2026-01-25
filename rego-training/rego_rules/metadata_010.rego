package metadata_010

import rego.v1

# METADATA
# title: Verify the build finished after it started.
# description: >-
#   Verify the build finished after it started.
# custom:
#   short_name: metadata_010
#
deny contains result if {
	some attestation in input.attestations
	started := time.parse_rfc3339_ns(attestation.statement.predicate.metadata.buildStartedOn)
	finished := time.parse_rfc3339_ns(attestation.statement.predicate.metadata.buildFinishedOn)
	finished <= started
	result := "Build finished before or at the same time as it started"
}
