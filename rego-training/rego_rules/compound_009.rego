package compound_009

import rego.v1

#
# METADATA
# title: Verify all tasks in the PipelineRun attestation that have a 'mode' parameter do not have it set to 'permissive'.
# description: >-
#   Verify all tasks in the PipelineRun attestation that have a 'mode' parameter do not have it set to 'permissive'.
# custom:
#   short_name: compound_009
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.invocation.parameters.mode == "permissive"
	result := sprintf("Task %s has mode parameter set to permissive", [task.name])
}
