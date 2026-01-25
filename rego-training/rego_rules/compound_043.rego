package compound_043

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have steps with environment image set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have steps with environment image set.
# custom:
#   short_name: compound_043
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some step in task.steps
	not step.environment.image
	result := sprintf("Task %s has step without environment image", [task.name])
}
