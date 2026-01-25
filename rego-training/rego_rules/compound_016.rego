package compound_016

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have a started timestamp.
# description: >-
#   Verify all tasks in the PipelineRun attestation have a started timestamp.
# custom:
#   short_name: compound_016
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.startedOn
	result := sprintf("Task %s does not have startedOn timestamp", [task.name])
}
