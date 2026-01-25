package step_030

import rego.v1

# METADATA
# title: Verify all steps in all tasks have arguments.
# description: >-
#   Verify all steps in all tasks have arguments.
# custom:
#   short_name: step_030
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some step in task.steps
	not step.arguments
	result := sprintf("Task %s has step without arguments", [task.name])
}
