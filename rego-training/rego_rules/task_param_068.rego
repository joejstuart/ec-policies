package task_param_068

import rego.v1

# METADATA
# title: Verify the build task has the skip-checks parameter set.
# description: >-
#   Verify the build task has the skip-checks parameter set.
# custom:
#   short_name: task_param_068
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	not task.invocation.parameters["skip-checks"]
	result := "build task does not have skip-checks parameter"
}
