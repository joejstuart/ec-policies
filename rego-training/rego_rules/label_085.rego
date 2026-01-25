package label_085

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the label 'tekton.dev/pipelineRunUID' set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the label 'tekton.dev/pipelineRunUID' set.
# custom:
#   short_name: label_085
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	labels := task.invocation.environment.labels
	labels
	count(labels) > 0
	not labels["tekton.dev/pipelineRunUID"]
	result := sprintf("Task %s does not have label tekton.dev/pipelineRunUID", [task.name])
}
