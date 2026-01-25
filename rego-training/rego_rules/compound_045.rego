package compound_045

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation that have annotations have at least one annotation set.
# description: >-
#   Verify all tasks in the PipelineRun attestation that have annotations have at least one annotation set.
# custom:
#   short_name: compound_045
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	annotations := task.invocation.environment.annotations
	annotations
	count(annotations) == 0
	result := sprintf("Task %s has empty annotations object", [task.name])
}
