package task_024

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have a configSource with entryPoint.
# description: >-
#   Verify all tasks in the PipelineRun attestation have a configSource with entryPoint.
# custom:
#   short_name: task_024
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.invocation.configSource.entryPoint
	result := sprintf("Task %s configSource does not have entryPoint", [task.name])
}
