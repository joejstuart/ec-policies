package compound_021

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have invocation environment.
# description: >-
#   Verify all tasks in the PipelineRun attestation have invocation environment.
# custom:
#   short_name: compound_021
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.invocation.environment
	result := sprintf("Task %s does not have invocation environment", [task.name])
}
