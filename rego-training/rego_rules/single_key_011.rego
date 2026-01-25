package single_key_011

import rego.v1

# METADATA
# title: Verify the build task has the annotation 'tekton.dev/tags' set to 'konflux'.
# description: >-
#   Verify the build task has the annotation 'tekton.dev/tags' set to 'konflux'.
# custom:
#   short_name: single_key_011
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	annotations := task.invocation.environment.annotations
	annotations["tekton.dev/tags"] != "konflux"
	result := "Build task does not have annotation tekton.dev/tags=konflux"
}
