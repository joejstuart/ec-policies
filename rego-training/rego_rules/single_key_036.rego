package single_key_036

import rego.v1

# METADATA
# title: Verify the build task has the label 'tekton.dev/task' set.
# description: >-
#   Verify the build task has the label 'tekton.dev/task' set.
# custom:
#   short_name: single_key_036
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	labels := task.invocation.environment.labels
	labels
	count(labels) > 0
	not labels["tekton.dev/task"]
	result := "Build task does not have label tekton.dev/task"
}
