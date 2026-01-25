package step_029

import rego.v1

# METADATA
# title: Verify the build task has at least one step with arguments.
# description: >-
#   Verify the build task has at least one step with arguments.
# custom:
#   short_name: step_029
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	some step in task.steps
	not step.arguments
	result := "Build task has step without arguments"
}
