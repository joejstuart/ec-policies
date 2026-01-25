package single_key_033

import rego.v1

# METADATA
# title: Verify the build task has the label 'tekton.dev/pipeline' set.
# description: >-
#   Verify the build task has the label 'tekton.dev/pipeline' set.
# custom:
#   short_name: single_key_033
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	labels := task.invocation.environment.labels
	labels
	count(labels) > 0
	not labels["tekton.dev/pipeline"]
	result := "Build task does not have label tekton.dev/pipeline"
}
