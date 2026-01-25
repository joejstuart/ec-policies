package single_key_027

import rego.v1

# METADATA
# title: Verify the build task has the label 'appstudio.openshift.io/component' set.
# description: >-
#   Verify the build task has the label 'appstudio.openshift.io/component' set.
# custom:
#   short_name: single_key_027
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	labels := task.invocation.environment.labels
	labels
	count(labels) > 0
	not labels["appstudio.openshift.io/component"]
	result := "Build task does not have label appstudio.openshift.io/component"
}
