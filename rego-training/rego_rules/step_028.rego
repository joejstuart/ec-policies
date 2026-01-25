package step_028

import rego.v1

# METADATA
# title: Verify all steps in all tasks have annotations.
# description: >-
#   Verify all steps in all tasks have annotations.
# custom:
#   short_name: step_028
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some step in task.steps
	not step.annotations
	result := sprintf("Task %s has step without annotations", [task.name])
}
