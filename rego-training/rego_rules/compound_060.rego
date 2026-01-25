package compound_060

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the annotation 'pipelinesascode.tekton.dev/state' set to 'completed'.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the annotation 'pipelinesascode.tekton.dev/state' set to 'completed'.
# custom:
#   short_name: compound_060
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	annotations := task.invocation.environment.annotations
	annotations["pipelinesascode.tekton.dev/state"] != "completed"
	result := sprintf("Task %s annotation pipelinesascode.tekton.dev/state is not completed", [task.name])
}
