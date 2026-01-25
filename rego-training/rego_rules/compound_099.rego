package compound_099

import rego.v1

# METADATA
# title: Verify all tasks have matching pipeline and pipelineRun in both annotations and labels.
# description: >-
#   Verify all tasks have matching pipeline and pipelineRun in both annotations and labels.
# custom:
#   short_name: compound_099
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	annotations := task.invocation.environment.annotations
	labels := task.invocation.environment.labels
	pipeline_ann := annotations["tekton.dev/pipeline"]
	pipeline_label := labels["tekton.dev/pipeline"]
	pipeline_ann
	pipeline_label
	pipeline_ann != pipeline_label
	result := sprintf("Task %s has mismatched pipeline in annotations and labels", [task.name])
}
