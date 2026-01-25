package label_086

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the label 'appstudio.openshift.io/application' set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the label 'appstudio.openshift.io/application' set.
# custom:
#   short_name: label_086
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	labels := task.invocation.environment.labels
	labels
	count(labels) > 0
	not labels["appstudio.openshift.io/application"]
	result := sprintf("Task %s does not have label appstudio.openshift.io/application", [task.name])
}
