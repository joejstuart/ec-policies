package compound_017

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation finished after they started.
# description: >-
#   Verify all tasks in the PipelineRun attestation finished after they started.
# custom:
#   short_name: compound_017
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	started := time.parse_rfc3339_ns(task.startedOn)
	finished := time.parse_rfc3339_ns(task.finishedOn)
	finished <= started
	result := sprintf("Task %s finished before or at the same time as it started", [task.name])
}
