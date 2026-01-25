package compound_023

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have invocation environment labels.
# description: >-
#   Verify all tasks in the PipelineRun attestation have invocation environment labels.
# custom:
#   short_name: compound_023
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.invocation.environment.labels
	result := sprintf("Task %s does not have invocation environment labels", [task.name])
}
