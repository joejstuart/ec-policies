package single_key_024

import rego.v1

# METADATA
# title: Verify the test task produced a result named 'TEST_OUTPUT'.
# description: >-
#   Verify the test task produced a result named 'TEST_OUTPUT'.
# custom:
#   short_name: single_key_024
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "test"
	not "TEST_OUTPUT" in {r.name | some r in task.results}
	result := "Test task did not produce TEST_OUTPUT result"
}
