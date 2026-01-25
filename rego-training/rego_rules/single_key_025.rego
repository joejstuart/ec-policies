package single_key_025

import rego.v1

# METADATA
# title: Verify the test task's TEST_OUTPUT result has a non-empty value.
# description: >-
#   Verify the test task's TEST_OUTPUT result has a non-empty value.
# custom:
#   short_name: single_key_025
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "test"
	some task_result in task.results
	task_result.name == "TEST_OUTPUT"
	task_result.value == ""
	result := "Test task TEST_OUTPUT result is empty"
}
