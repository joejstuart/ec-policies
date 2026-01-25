package compound_033

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the label 'tekton.dev/task' set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the label 'tekton.dev/task' set.
# custom:
#   short_name: compound_033
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	labels := task.invocation.environment.labels
	labels
	count(labels) > 0
	not labels["tekton.dev/task"]
	result := sprintf("Task %s does not have label tekton.dev/task", [task.name])
}
