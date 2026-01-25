package metadata_096

import rego.v1

# METADATA
# title: Verify the build completed within 24 hours of starting.
# description: >-
#   Verify the build completed within 24 hours of starting.
# custom:
#   short_name: metadata_096
#
deny contains result if {
	some attestation in input.attestations
	started := time.parse_rfc3339_ns(attestation.statement.predicate.metadata.buildStartedOn)
	finished := time.parse_rfc3339_ns(attestation.statement.predicate.metadata.buildFinishedOn)
	duration_hours := (finished - started) / 3600000000000
	duration_hours > 24
	result := sprintf("Build took %d hours, exceeds 24 hour limit", [duration_hours])
}
