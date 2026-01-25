package compound_042

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have steps with environment set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have steps with environment set.
# custom:
#   short_name: compound_042
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	some step in task.steps
	not step.environment
	result := sprintf("Task %s has step without environment", [task.name])
}
