package single_key_040

import rego.v1

# METADATA
# title: Verify the build task has the annotation 'tekton.dev/pipelines.minVersion' set.
# description: >-
#   Verify the build task has the annotation 'tekton.dev/pipelines.minVersion' set.
# custom:
#   short_name: single_key_040
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	annotations := task.invocation.environment.annotations
	annotations
	count(annotations) > 0
	not annotations["tekton.dev/pipelines.minVersion"]
	result := "Build task does not have annotation tekton.dev/pipelines.minVersion"
}
