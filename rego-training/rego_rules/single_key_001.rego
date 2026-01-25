package single_key_001

import rego.v1

# METADATA
# title: Verify the build task has status 'Succeeded'.
# description: >-
#   Verify the build task has status 'Succeeded'.
# custom:
#   short_name: single_key_001
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	task.status != "Succeeded"
	result := sprintf("Build task status is %s, expected Succeeded", [task.status])
}
