package compound_059

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the label 'pipelines.appstudio.openshift.io/type' set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the label 'pipelines.appstudio.openshift.io/type' set.
# custom:
#   short_name: compound_059
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	labels := task.invocation.environment.labels
	labels
	count(labels) > 0
	not labels["pipelines.appstudio.openshift.io/type"]
	result := sprintf("Task %s does not have label pipelines.appstudio.openshift.io/type", [task.name])
}
