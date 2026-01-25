package single_key_012

import rego.v1

# METADATA
# title: Verify the build task has the label 'tekton.dev/memberOf' set to 'tasks'.
# description: >-
#   Verify the build task has the label 'tekton.dev/memberOf' set to 'tasks'.
# custom:
#   short_name: single_key_012
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	labels := task.invocation.environment.labels
	labels["tekton.dev/memberOf"] != "tasks"
	result := "Build task does not have label tekton.dev/memberOf=tasks"
}
