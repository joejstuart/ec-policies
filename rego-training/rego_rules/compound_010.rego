package compound_010

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation that have an 'sslVerify' parameter have it set to 'true'.
# description: >-
#   Verify all tasks in the PipelineRun attestation that have an 'sslVerify' parameter have it set to 'true'.
# custom:
#   short_name: compound_010
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.invocation.parameters.sslVerify
	task.invocation.parameters.sslVerify != "true"
	result := sprintf("Task %s has sslVerify parameter set to %s, expected true", [task.name, task.invocation.parameters.sslVerify])
}
