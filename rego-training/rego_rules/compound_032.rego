package compound_032

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the label 'tekton.dev/pipelineTask' set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the label 'tekton.dev/pipelineTask' set.
# custom:
#   short_name: compound_032
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	labels := task.invocation.environment.labels
	labels
	count(labels) > 0
	not labels["tekton.dev/pipelineTask"]
	result := sprintf("Task %s does not have label tekton.dev/pipelineTask", [task.name])
}
