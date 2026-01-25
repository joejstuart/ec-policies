package task_param_196

import rego.v1

# METADATA
# title: Verify the build task has the 'skip-checks' parameter set to 'false'.
# description: >-
#   Verify the build task has the 'skip-checks' parameter set to 'false'.
# custom:
#   short_name: task_param_196
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	task.invocation.parameters["skip-checks"] == "true"
	result := "Build task skip-checks parameter is set to true"
}
