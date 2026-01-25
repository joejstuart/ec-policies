package compound_014

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the annotation 'tekton.dev/pipelines.minVersion' set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the annotation 'tekton.dev/pipelines.minVersion' set.
# custom:
#   short_name: compound_014
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	annotations := task.invocation.environment.annotations
	annotations
	count(annotations) > 0
	not annotations["tekton.dev/pipelines.minVersion"]
	result := sprintf("Task %s does not have annotation tekton.dev/pipelines.minVersion", [task.name])
}
