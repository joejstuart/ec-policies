package single_key_037

import rego.v1

# METADATA
# title: Verify the build task has the annotation 'results.tekton.dev/result' set.
# description: >-
#   Verify the build task has the annotation 'results.tekton.dev/result' set.
# custom:
#   short_name: single_key_037
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	annotations := task.invocation.environment.annotations
	annotations
	count(annotations) > 0
	not annotations["results.tekton.dev/result"]
	result := "Build task does not have annotation results.tekton.dev/result"
}
