package compound_011

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the label 'tekton.dev/memberOf' set to 'tasks'.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the label 'tekton.dev/memberOf' set to 'tasks'.
# custom:
#   short_name: compound_011
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	labels := task.invocation.environment.labels
	labels["tekton.dev/memberOf"] != "tasks"
	result := sprintf("Task %s does not have label tekton.dev/memberOf=tasks", [task.name])
}
