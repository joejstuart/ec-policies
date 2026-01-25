package compound_041

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have steps with entryPoint set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have steps with entryPoint set.
# custom:
#   short_name: compound_041
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some step in task.steps
	not step.entryPoint
	result := sprintf("Task %s has step without entryPoint", [task.name])
}
