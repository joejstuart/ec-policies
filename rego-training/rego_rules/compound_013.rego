package compound_013

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the label 'app.kubernetes.io/version' set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the label 'app.kubernetes.io/version' set.
# custom:
#   short_name: compound_013
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	labels := task.invocation.environment.labels
	labels
	count(labels) > 0
	not labels["app.kubernetes.io/version"]
	result := sprintf("Task %s does not have label app.kubernetes.io/version", [task.name])
}
