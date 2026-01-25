package compound_008

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have a reference with a name.
# description: >-
#   Verify all tasks in the PipelineRun attestation have a reference with a name.
# custom:
#   short_name: compound_008
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.ref.name
	result := sprintf("Task %s reference does not have a name", [task.name])
}
