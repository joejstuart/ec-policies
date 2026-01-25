package single_key_002

import rego.v1

# METADATA
# title: Verify the test task has status 'Succeeded'.
# description: >-
#   Verify the test task has status 'Succeeded'.
# custom:
#   short_name: single_key_002
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "test"
	task.status != "Succeeded"
	result := sprintf("Test task status is %s, expected Succeeded", [task.status])
}
