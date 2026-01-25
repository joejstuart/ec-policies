package compound_012

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the label 'app.kubernetes.io/managed-by' set to 'tekton-pipelines'.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the label 'app.kubernetes.io/managed-by' set to 'tekton-pipelines'.
# custom:
#   short_name: compound_012
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	labels := task.invocation.environment.labels
	labels["app.kubernetes.io/managed-by"] != "tekton-pipelines"
	result := sprintf("Task %s does not have label app.kubernetes.io/managed-by=tekton-pipelines", [task.name])
}
