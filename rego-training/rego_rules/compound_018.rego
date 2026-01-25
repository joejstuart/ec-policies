package compound_018

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have at least one result.
# description: >-
#   Verify all tasks in the PipelineRun attestation have at least one result.
# custom:
#   short_name: compound_018
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	count(task.results) == 0
	result := sprintf("Task %s has no results", [task.name])
}
