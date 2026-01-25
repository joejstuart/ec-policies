package compound_044

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation that have parameters have at least one parameter set.
# description: >-
#   Verify all tasks in the PipelineRun attestation that have parameters have at least one parameter set.
# custom:
#   short_name: compound_044
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.invocation.parameters
	count(task.invocation.parameters) == 0
	result := sprintf("Task %s has empty parameters object", [task.name])
}
