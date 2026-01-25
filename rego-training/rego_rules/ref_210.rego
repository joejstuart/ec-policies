package ref_210

import rego.v1

# METADATA
# title: Verify all tasks have reference kind that is not empty.
# description: >-
#   Verify all tasks have reference kind that is not empty.
# custom:
#   short_name: ref_210
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.ref.kind == ""
	result := sprintf("Task %s reference has empty kind", [task.name])
}
