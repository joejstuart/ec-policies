package compound_049

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have reference names that are not empty strings.
# description: >-
#   Verify all tasks in the PipelineRun attestation have reference names that are not empty strings.
# custom:
#   short_name: compound_049
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.ref.name == ""
	result := sprintf("Task %s has empty reference name", [task.name])
}
