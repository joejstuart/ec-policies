package single_key_039

import rego.v1

# METADATA
# title: Verify the build task has the annotation 'results.tekton.dev/stored' set to 'true'.
# description: >-
#   Verify the build task has the annotation 'results.tekton.dev/stored' set to 'true'.
# custom:
#   short_name: single_key_039
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	annotations := task.invocation.environment.annotations
	annotations["results.tekton.dev/stored"] != "true"
	result := "Build task annotation results.tekton.dev/stored is not true"
}
