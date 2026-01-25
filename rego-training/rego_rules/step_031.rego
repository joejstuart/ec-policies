package step_031

import rego.v1

# METADATA
# title: Verify the build task has at least one step with environment container set.
# description: >-
#   Verify the build task has at least one step with environment container set.
# custom:
#   short_name: step_031
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	some step in task.steps
	not step.environment.container
	result := "Build task has step without environment container"
}
