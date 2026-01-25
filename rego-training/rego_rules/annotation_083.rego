package annotation_083

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the annotation 'pipelinesascode.tekton.dev/sender' set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the annotation 'pipelinesascode.tekton.dev/sender' set.
# custom:
#   short_name: annotation_083
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	annotations := task.invocation.environment.annotations
	annotations
	count(annotations) > 0
	not annotations["pipelinesascode.tekton.dev/sender"]
	result := sprintf("Task %s does not have annotation pipelinesascode.tekton.dev/sender", [task.name])
}
