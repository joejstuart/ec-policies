package compound_004

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have a status set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have a status set.
# custom:
#   short_name: compound_004
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.status
	result := sprintf("Task %s does not have a status", [task.name])
}
