package annotation_049

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the annotation 'pipelinesascode.tekton.dev/state' set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the annotation 'pipelinesascode.tekton.dev/state' set.
# custom:
#   short_name: annotation_049
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	annotations := task.invocation.environment.annotations
	annotations
	count(annotations) > 0
	not annotations["pipelinesascode.tekton.dev/state"]
	result := sprintf("Task %s does not have annotation pipelinesascode.tekton.dev/state", [task.name])
}
