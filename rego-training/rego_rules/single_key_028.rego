package single_key_028

import rego.v1

# METADATA
# title: Verify the build task finished after it started.
# description: >-
#   Verify the build task finished after it started.
# custom:
#   short_name: single_key_028
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	started := time.parse_rfc3339_ns(task.startedOn)
	finished := time.parse_rfc3339_ns(task.finishedOn)
	finished <= started
	result := "Build task finished before or at the same time as it started"
}
