package ref_209

import rego.v1

# METADATA
# title: Verify all tasks have reference name that is not empty.
# description: >-
#   Verify all tasks have reference name that is not empty.
# custom:
#   short_name: ref_209
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.ref.name == ""
	result := sprintf("Task %s reference has empty name", [task.name])
}
