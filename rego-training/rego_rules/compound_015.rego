package compound_015

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have a finished timestamp.
# description: >-
#   Verify all tasks in the PipelineRun attestation have a finished timestamp.
# custom:
#   short_name: compound_015
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.finishedOn
	result := sprintf("Task %s does not have finishedOn timestamp", [task.name])
}
