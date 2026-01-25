package single_key_032

import rego.v1

# METADATA
# title: Verify the build task has the annotation 'pipeline.tekton.dev/release' set.
# description: >-
#   Verify the build task has the annotation 'pipeline.tekton.dev/release' set.
# custom:
#   short_name: single_key_032
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	annotations := task.invocation.environment.annotations
	annotations
	count(annotations) > 0
	not annotations["pipeline.tekton.dev/release"]
	result := "Build task does not have annotation pipeline.tekton.dev/release"
}
