package task_param_069

import rego.v1

# METADATA
# title: Verify the test task has the test-command parameter set.
# description: >-
#   Verify the test task has the test-command parameter set.
# custom:
#   short_name: task_param_069
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "test"
	not task.invocation.parameters["test-command"]
	result := "test task does not have test-command parameter"
}
