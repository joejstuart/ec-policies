package step_089

import rego.v1

# METADATA
# title: Verify all steps in all tasks that have arguments have at least one argument.
# description: >-
#   Verify all steps in all tasks that have arguments have at least one argument.
# custom:
#   short_name: step_089
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some step in task.steps
	step.arguments
	count(step.arguments) == 0
	result := sprintf("Task %s has step with empty arguments array", [task.name])
}
