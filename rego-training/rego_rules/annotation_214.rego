package annotation_214

import rego.v1

# METADATA
# title: Verify all tasks have annotation values that are not empty when the annotation exists.
# description: >-
#   Verify all tasks have annotation values that are not empty when the annotation exists.
# custom:
#   short_name: annotation_214
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some annotation_key, annotation_value in task.invocation.environment.annotations
	annotation_value == ""
	result := sprintf("Task %s has annotation %s with empty value", [task.name, annotation_key])
}
