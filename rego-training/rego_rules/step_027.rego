package step_027

import rego.v1

# METADATA
# title: Verify the build task has at least one step with annotations.
# description: >-
#   Verify the build task has at least one step with annotations.
# custom:
#   short_name: step_027
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	some step in task.steps
	not step.annotations
	result := "Build task has step without annotations"
}
