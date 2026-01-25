package single_key_034

import rego.v1

# METADATA
# title: Verify the build task has the label 'tekton.dev/pipelineRun' set.
# description: >-
#   Verify the build task has the label 'tekton.dev/pipelineRun' set.
# custom:
#   short_name: single_key_034
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	labels := task.invocation.environment.labels
	labels
	count(labels) > 0
	not labels["tekton.dev/pipelineRun"]
	result := "Build task does not have label tekton.dev/pipelineRun"
}
