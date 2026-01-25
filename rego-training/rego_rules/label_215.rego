package label_215

import rego.v1

# METADATA
# title: Verify all tasks have label values that are not empty when the label exists.
# description: >-
#   Verify all tasks have label values that are not empty when the label exists.
# custom:
#   short_name: label_215
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some label_key, label_value in task.invocation.environment.labels
	label_value == ""
	result := sprintf("Task %s has label %s with empty value", [task.name, label_key])
}
