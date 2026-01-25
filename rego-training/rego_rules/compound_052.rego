package compound_052

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have finished timestamps that are valid RFC3339 format.
# description: >-
#   Verify all tasks in the PipelineRun attestation have finished timestamps that are valid RFC3339 format.
# custom:
#   short_name: compound_052
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	finished := task.finishedOn
	finished
	not time.parse_rfc3339_ns(finished)
	result := sprintf("Task %s has invalid finishedOn timestamp format: %s", [task.name, finished])
}
