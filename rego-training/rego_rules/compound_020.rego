package compound_020

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have invocation parameters.
# description: >-
#   Verify all tasks in the PipelineRun attestation have invocation parameters.
# custom:
#   short_name: compound_020
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.invocation.parameters
	result := sprintf("Task %s does not have invocation parameters", [task.name])
}
