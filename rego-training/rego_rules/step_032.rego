package step_032

import rego.v1

# METADATA
# title: Verify all steps in all tasks have environment container set.
# description: >-
#   Verify all steps in all tasks have environment container set.
# custom:
#   short_name: step_032
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some step in task.steps
	not step.environment.container
	result := sprintf("Task %s has step without environment container", [task.name])
}
