package compound_024

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have a configSource.
# description: >-
#   Verify all tasks in the PipelineRun attestation have a configSource.
# custom:
#   short_name: compound_024
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.invocation.configSource
	result := sprintf("Task %s does not have configSource", [task.name])
}
