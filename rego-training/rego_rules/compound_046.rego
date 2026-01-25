package compound_046

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation that have labels have at least one label set.
# description: >-
#   Verify all tasks in the PipelineRun attestation that have labels have at least one label set.
# custom:
#   short_name: compound_046
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	labels := task.invocation.environment.labels
	labels
	count(labels) == 0
	result := sprintf("Task %s has empty labels object", [task.name])
}
