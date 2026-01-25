package compound_050

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have names that are not empty strings.
# description: >-
#   Verify all tasks in the PipelineRun attestation have names that are not empty strings.
# custom:
#   short_name: compound_050
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == ""
	result := "Task has empty name"
}
