package compound_030

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the label 'tekton.dev/pipeline' set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the label 'tekton.dev/pipeline' set.
# custom:
#   short_name: compound_030
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	labels := task.invocation.environment.labels
	labels
	count(labels) > 0
	not labels["tekton.dev/pipeline"]
	result := sprintf("Task %s does not have label tekton.dev/pipeline", [task.name])
}
