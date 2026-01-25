package label_087

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the label 'appstudio.openshift.io/component' set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the label 'appstudio.openshift.io/component' set.
# custom:
#   short_name: label_087
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	labels := task.invocation.environment.labels
	labels
	count(labels) > 0
	not labels["appstudio.openshift.io/component"]
	result := sprintf("Task %s does not have label appstudio.openshift.io/component", [task.name])
}
