package compound_005

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have a name.
# description: >-
#   Verify all tasks in the PipelineRun attestation have a name.
# custom:
#   short_name: compound_005
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.name
	result := "Task does not have a name"
}
