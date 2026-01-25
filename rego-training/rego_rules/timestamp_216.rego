package timestamp_216

import rego.v1

# METADATA
# title: Verify all tasks that have startedOn have it in valid RFC3339 format.
# description: >-
#   Verify all tasks that have startedOn have it in valid RFC3339 format.
# custom:
#   short_name: timestamp_216
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	started := task.startedOn
	started
	not time.parse_rfc3339_ns(started)
	result := sprintf("Task %s has invalid startedOn timestamp format: %s", [task.name, started])
}
