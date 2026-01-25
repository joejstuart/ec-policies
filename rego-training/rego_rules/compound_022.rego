package compound_022

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have invocation environment annotations.
# description: >-
#   Verify all tasks in the PipelineRun attestation have invocation environment annotations.
# custom:
#   short_name: compound_022
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.invocation.environment.annotations
	result := sprintf("Task %s does not have invocation environment annotations", [task.name])
}
