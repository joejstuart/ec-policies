package task_param_195

import rego.v1

# METADATA
# title: Verify the build task has the 'rebuild' parameter set to 'false'.
# description: >-
#   Verify the build task has the 'rebuild' parameter set to 'false'.
# custom:
#   short_name: task_param_195
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	task.invocation.parameters.rebuild == "true"
	result := "Build task rebuild parameter is set to true"
}
