package compound_224

import rego.v1

# METADATA
# title: Verify all tasks that have steps have at least one step with a non-empty entryPoint.
# description: >-
#   Verify all tasks that have steps have at least one step with a non-empty entryPoint.
# custom:
#   short_name: compound_224
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	count(task.steps) > 0
	all_empty := {step.entryPoint | some step in task.steps; step.entryPoint == ""}
	count(all_empty) == count(task.steps)
	result := sprintf("Task %s has all steps with empty entryPoint", [task.name])
}
